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

package keyprovider

import (
	"context"
	"crypto/x509"
	"testing"
)

const mockProvider = "mock-provider"

type mockKeyProvider struct{}

func (m *mockKeyProvider) GetCertificates(_ context.Context) ([]*x509.Certificate, error) {
	return nil, nil
}

func (m *mockKeyProvider) GetKeys(_ context.Context) ([]*PublicKey, error) {
	return nil, nil
}

func TestCreateKeyProvider(t *testing.T) {
	RegisterKeyProvider(mockProvider, func(_ any) (KeyProvider, error) {
		return &mockKeyProvider{}, nil
	})

	provider, err := CreateKeyProvider(mockProvider, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil key provider")
	}

	if _, err = CreateKeyProvider("unknown-provider", nil); err == nil {
		t.Fatal("expected error, got nil")
	}
}
