/*
Copyright The Ratify Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package aws

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/notaryproject/ratify/v2/internal/store/credentialprovider"
)

// fakeTTLLogger records warnings emitted by resolveTokenTTL.
type fakeTTLLogger struct {
	warned bool
}

func (l *fakeTTLLogger) Warnf(string, ...interface{}) { l.warned = true }

// mockECRClient is a mock implementation of authTokenGetter.
type mockECRClient struct {
	output *ecr.GetAuthorizationTokenOutput
	err    error
}

func (m *mockECRClient) GetAuthorizationToken(_ context.Context, _ *ecr.GetAuthorizationTokenInput, _ ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error) {
	return m.output, m.err
}

func TestCreateAWSProvider(t *testing.T) {
	tests := []struct {
		name        string
		opts        credentialprovider.Options
		expectError bool
	}{
		{
			name: "valid with region",
			opts: credentialprovider.Options{"provider": "aws", "region": "us-east-1"},
		},
		{
			name: "valid without region",
			opts: credentialprovider.Options{"provider": "aws"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := createAWSProvider(tt.opts)
			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == nil {
				t.Fatalf("expected a provider, got nil")
			}
		})
	}
}

func TestRegionFromRegistry(t *testing.T) {
	tests := []struct {
		name        string
		registry    string
		want        string
		expectError bool
	}{
		{name: "standard", registry: "123456789012.dkr.ecr.us-east-1.amazonaws.com", want: "us-east-1"},
		{name: "china partition", registry: "123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn", want: "cn-north-1"},
		{name: "not ecr", registry: "myregistry.azurecr.io", expectError: true},
		{name: "too short", registry: "foo.bar.com", expectError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := regionFromRegistry(tt.registry)
			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("region = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecodeAuthToken(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		wantUser    string
		wantPass    string
		expectError bool
	}{
		{
			name:     "valid",
			token:    base64.StdEncoding.EncodeToString([]byte("AWS:secret")),
			wantUser: "AWS",
			wantPass: "secret",
		},
		{
			name:     "password with colon",
			token:    base64.StdEncoding.EncodeToString([]byte("AWS:sec:ret")),
			wantUser: "AWS",
			wantPass: "sec:ret",
		},
		{name: "empty", token: "", expectError: true},
		{name: "not base64", token: "%%%not-base64%%%", expectError: true},
		{name: "no colon", token: base64.StdEncoding.EncodeToString([]byte("nocolon")), expectError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, pass, err := decodeAuthToken(tt.token)
			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if user != tt.wantUser || pass != tt.wantPass {
				t.Fatalf("got (%q,%q), want (%q,%q)", user, pass, tt.wantUser, tt.wantPass)
			}
		})
	}
}

func TestResolveTokenTTL(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name       string
		expiresAt  *time.Time
		wantZero   bool
		wantWarned bool
	}{
		{name: "nil expiry", expiresAt: nil, wantZero: true, wantWarned: true},
		{name: "expired", expiresAt: ptrTime(now.Add(-time.Hour)), wantZero: true, wantWarned: true},
		{name: "valid", expiresAt: ptrTime(now.Add(12 * time.Hour)), wantZero: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := &fakeTTLLogger{}
			ttl := resolveTokenTTL(log, "registry", tt.expiresAt)
			if tt.wantZero && ttl != 0 {
				t.Fatalf("expected zero TTL, got %s", ttl)
			}
			if !tt.wantZero && ttl <= 0 {
				t.Fatalf("expected positive TTL, got %s", ttl)
			}
			if log.warned != tt.wantWarned {
				t.Fatalf("warned = %v, want %v", log.warned, tt.wantWarned)
			}
		})
	}
}

func TestGetWithTTL(t *testing.T) {
	validToken := base64.StdEncoding.EncodeToString([]byte("AWS:secret"))
	expiry := time.Now().Add(12 * time.Hour)

	tests := []struct {
		name          string
		region        string
		serverAddress string
		client        *mockECRClient
		clientErr     error
		expectError   bool
		wantUser      string
		wantPass      string
	}{
		{
			name:          "success derives region",
			serverAddress: "123456789012.dkr.ecr.us-west-2.amazonaws.com",
			client: &mockECRClient{output: &ecr.GetAuthorizationTokenOutput{
				AuthorizationData: []types.AuthorizationData{{
					AuthorizationToken: aws.String(validToken),
					ExpiresAt:          &expiry,
				}},
			}},
			wantUser: "AWS",
			wantPass: "secret",
		},
		{
			name:          "success with explicit region",
			region:        "eu-central-1",
			serverAddress: "notaregistry",
			client: &mockECRClient{output: &ecr.GetAuthorizationTokenOutput{
				AuthorizationData: []types.AuthorizationData{{
					AuthorizationToken: aws.String(validToken),
					ExpiresAt:          &expiry,
				}},
			}},
			wantUser: "AWS",
			wantPass: "secret",
		},
		{
			name:          "invalid registry without region",
			serverAddress: "myregistry.azurecr.io",
			client:        &mockECRClient{},
			expectError:   true,
		},
		{
			name:          "ecr error",
			serverAddress: "123456789012.dkr.ecr.us-west-2.amazonaws.com",
			client:        &mockECRClient{err: errors.New("boom")},
			expectError:   true,
		},
		{
			name:          "no auth data",
			serverAddress: "123456789012.dkr.ecr.us-west-2.amazonaws.com",
			client:        &mockECRClient{output: &ecr.GetAuthorizationTokenOutput{}},
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &IdentityProvider{
				region: tt.region,
				newClient: func(context.Context, string) (authTokenGetter, error) {
					return tt.client, nil
				},
			}
			got, err := p.GetWithTTL(context.Background(), tt.serverAddress)
			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Credential.Username != tt.wantUser || got.Credential.Password != tt.wantPass {
				t.Fatalf("got (%q,%q), want (%q,%q)", got.Credential.Username, got.Credential.Password, tt.wantUser, tt.wantPass)
			}
			if got.TTL <= 0 {
				t.Fatalf("expected positive TTL, got %s", got.TTL)
			}
		})
	}
}

func TestGetWithTTLClientError(t *testing.T) {
	p := &IdentityProvider{
		region: "us-east-1",
		newClient: func(context.Context, string) (authTokenGetter, error) {
			return nil, errors.New("failed to build client")
		},
	}
	if _, err := p.GetWithTTL(context.Background(), "123456789012.dkr.ecr.us-east-1.amazonaws.com"); err == nil {
		t.Fatalf("expected error when client construction fails, got nil")
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
