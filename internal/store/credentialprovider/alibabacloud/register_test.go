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

package alibabacloud

import (
	"context"
	"errors"
	"testing"
	"time"

	cr20181201 "github.com/alibabacloud-go/cr-20181201/v2/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/notaryproject/ratify/v2/internal/store/credentialprovider"
)

// fakeTTLLogger records warnings emitted by resolveTokenTTL.
type fakeTTLLogger struct {
	warned bool
}

func (l *fakeTTLLogger) Warnf(string, ...interface{}) { l.warned = true }

// mockACRTokenGetter is a mock implementation of acrTokenGetter.
type mockACRTokenGetter struct {
	body          *cr20181201.GetAuthorizationTokenResponseBody
	err           error
	gotInstanceID string
	gotServerAddr string
}

func (m *mockACRTokenGetter) getACRToken(_ context.Context, serverAddress, instanceID string) (*cr20181201.GetAuthorizationTokenResponseBody, error) {
	m.gotInstanceID = instanceID
	m.gotServerAddr = serverAddress
	return m.body, m.err
}

// mockACRClient is a mock implementation of acrClient.
type mockACRClient struct {
	response *cr20181201.GetAuthorizationTokenResponse
	err      error
	gotID    string
}

func (m *mockACRClient) GetAuthorizationTokenWithOptions(request *cr20181201.GetAuthorizationTokenRequest, _ *util.RuntimeOptions) (*cr20181201.GetAuthorizationTokenResponse, error) {
	if request != nil {
		m.gotID = tea.StringValue(request.InstanceId)
	}
	return m.response, m.err
}

func TestDefaultACRTokenGetter(t *testing.T) {
	validResponse := &cr20181201.GetAuthorizationTokenResponse{
		Body: &cr20181201.GetAuthorizationTokenResponseBody{
			TempUsername:       tea.String("temp-user"),
			AuthorizationToken: tea.String("temp-token"),
		},
	}

	tests := []struct {
		name          string
		serverAddress string
		client        acrClient
		clientErr     error
		expectError   bool
		wantID        string
	}{
		{
			name:          "success",
			serverAddress: "my-registry.cn-hangzhou.cr.aliyuncs.com",
			client:        &mockACRClient{response: validResponse},
			wantID:        "cri-123",
		},
		{
			name:          "invalid host",
			serverAddress: "myregistry.azurecr.io",
			client:        &mockACRClient{response: validResponse},
			expectError:   true,
		},
		{
			name:          "client construction error",
			serverAddress: "my-registry.cn-hangzhou.cr.aliyuncs.com",
			clientErr:     errors.New("no credentials"),
			expectError:   true,
		},
		{
			name:          "api error",
			serverAddress: "my-registry.cn-hangzhou.cr.aliyuncs.com",
			client:        &mockACRClient{err: errors.New("boom")},
			expectError:   true,
		},
		{
			name:          "nil body",
			serverAddress: "my-registry.cn-hangzhou.cr.aliyuncs.com",
			client:        &mockACRClient{response: &cr20181201.GetAuthorizationTokenResponse{}},
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getter := &defaultACRTokenGetter{
				newClient: func(string) (acrClient, error) {
					if tt.clientErr != nil {
						return nil, tt.clientErr
					}
					return tt.client, nil
				},
			}
			body, err := getter.getACRToken(context.Background(), tt.serverAddress, "cri-123")
			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if body == nil {
				t.Fatalf("expected a body, got nil")
			}
			if mc, ok := tt.client.(*mockACRClient); ok && mc.gotID != tt.wantID {
				t.Fatalf("instance id = %q, want %q", mc.gotID, tt.wantID)
			}
		})
	}
}

// TestDefaultACRClient exercises the production client factory. Credential
// resolution is lazy, so construction succeeds and returns a usable client.
func TestDefaultACRClient(t *testing.T) {
	client, err := defaultACRClient("cn-hangzhou")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatalf("expected a client, got nil")
	}
}

func TestParseACRHost(t *testing.T) {
	tests := []struct {
		name         string
		host         string
		wantInstance string
		wantRegion   string
		expectError  bool
	}{
		{name: "shared instance", host: "registry.cn-hangzhou.cr.aliyuncs.com", wantInstance: "", wantRegion: "cn-hangzhou"},
		{name: "ee instance", host: "my-registry.cn-hangzhou.cr.aliyuncs.com", wantInstance: "my", wantRegion: "cn-hangzhou"},
		{name: "vpc endpoint", host: "test-registry-vpc.cn-hangzhou.cr.aliyuncs.com", wantInstance: "test", wantRegion: "cn-hangzhou"},
		{name: "v1 parity dahu vpc", host: "dahu-registry-vpc.cn-hangzhou.cr.aliyuncs.com", wantInstance: "dahu", wantRegion: "cn-hangzhou"},
		{name: "no cr label", host: "registry-vpc.cn-beijing.aliyuncs.com", wantInstance: "", wantRegion: "cn-beijing"},
		{name: "wrong suffix", host: "myregistry.azurecr.io", expectError: true},
		{name: "malformed", host: "foo.aliyuncs.com", expectError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta, err := parseACRHost(tt.host)
			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if meta.instanceName != tt.wantInstance || meta.region != tt.wantRegion {
				t.Fatalf("got (%q,%q), want (%q,%q)", meta.instanceName, meta.region, tt.wantInstance, tt.wantRegion)
			}
		})
	}
}

func TestCreateAlibabaCloudProvider(t *testing.T) {
	tests := []struct {
		name        string
		opts        credentialprovider.Options
		env         string
		expectError bool
	}{
		{
			name: "default instance id",
			opts: credentialprovider.Options{"provider": "alibabacloud", "defaultInstanceId": "cri-123"},
		},
		{
			name: "instance config only",
			opts: credentialprovider.Options{
				"provider": "alibabacloud",
				"acrInstancesConfig": []map[string]string{
					{"instanceName": "my", "instanceId": "cri-abc"},
				},
			},
		},
		{
			name:        "no instance configured",
			opts:        credentialprovider.Options{"provider": "alibabacloud"},
			expectError: true,
		},
		{
			name: "env fallback",
			opts: credentialprovider.Options{"provider": "alibabacloud"},
			env:  "cri-env",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env != "" {
				t.Setenv(envACRInstanceID, tt.env)
			}
			got, err := createAlibabaCloudProvider(tt.opts)
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

func TestResolveTokenTTL(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name       string
		expireMs   int64
		wantZero   bool
		wantWarned bool
	}{
		{name: "zero", expireMs: 0, wantZero: true, wantWarned: true},
		{name: "expired", expireMs: now.Add(-time.Hour).UnixMilli(), wantZero: true, wantWarned: true},
		{name: "valid", expireMs: now.Add(time.Hour).UnixMilli(), wantZero: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := &fakeTTLLogger{}
			ttl := resolveTokenTTL(log, "registry", tt.expireMs)
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
	expiry := time.Now().Add(time.Hour).UnixMilli()
	validBody := &cr20181201.GetAuthorizationTokenResponseBody{
		TempUsername:       tea.String("temp-user"),
		AuthorizationToken: tea.String("temp-token"),
		ExpireTime:         tea.Int64(expiry),
	}

	tests := []struct {
		name           string
		provider       *IdentityProvider
		serverAddress  string
		getter         *mockACRTokenGetter
		expectError    bool
		wantInstanceID string
		wantUser       string
		wantPass       string
	}{
		{
			name: "default instance",
			provider: &IdentityProvider{
				defaultInstanceID: "cri-default",
				instanceIDs:       map[string]string{},
			},
			serverAddress:  "registry.cn-hangzhou.cr.aliyuncs.com",
			getter:         &mockACRTokenGetter{body: validBody},
			wantInstanceID: "cri-default",
			wantUser:       "temp-user",
			wantPass:       "temp-token",
		},
		{
			name: "instance name mapping",
			provider: &IdentityProvider{
				defaultInstanceID: "cri-default",
				instanceIDs:       map[string]string{"my": "cri-my"},
			},
			serverAddress:  "my-registry.cn-hangzhou.cr.aliyuncs.com",
			getter:         &mockACRTokenGetter{body: validBody},
			wantInstanceID: "cri-my",
			wantUser:       "temp-user",
			wantPass:       "temp-token",
		},
		{
			name: "invalid host",
			provider: &IdentityProvider{
				defaultInstanceID: "cri-default",
				instanceIDs:       map[string]string{},
			},
			serverAddress: "myregistry.azurecr.io",
			getter:        &mockACRTokenGetter{body: validBody},
			expectError:   true,
		},
		{
			name: "no instance id resolved",
			provider: &IdentityProvider{
				defaultInstanceID: "",
				instanceIDs:       map[string]string{"other": "cri-other"},
			},
			serverAddress: "registry.cn-hangzhou.cr.aliyuncs.com",
			getter:        &mockACRTokenGetter{body: validBody},
			expectError:   true,
		},
		{
			name: "token getter error",
			provider: &IdentityProvider{
				defaultInstanceID: "cri-default",
				instanceIDs:       map[string]string{},
			},
			serverAddress: "registry.cn-hangzhou.cr.aliyuncs.com",
			getter:        &mockACRTokenGetter{err: errors.New("boom")},
			expectError:   true,
		},
		{
			name: "nil body",
			provider: &IdentityProvider{
				defaultInstanceID: "cri-default",
				instanceIDs:       map[string]string{},
			},
			serverAddress: "registry.cn-hangzhou.cr.aliyuncs.com",
			getter:        &mockACRTokenGetter{body: nil},
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.provider.tokenGetter = tt.getter
			got, err := tt.provider.GetWithTTL(context.Background(), tt.serverAddress)
			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.getter.gotInstanceID != tt.wantInstanceID {
				t.Fatalf("instance id = %q, want %q", tt.getter.gotInstanceID, tt.wantInstanceID)
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
