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

package azure

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

const testACRScope = "https://containerregistry.azure.net/.default"

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	return path
}

func TestLoadIdentityBindingConfigFromEnv(t *testing.T) {
	tests := []struct {
		name        string
		env         map[string]string
		expectNil   bool
		expectError bool
		assert      func(t *testing.T, cfg *IdentityBindingConfig)
	}{
		{
			name:      "not configured returns nil",
			env:       map[string]string{},
			expectNil: true,
		},
		{
			name: "sni without api server host errors",
			env: map[string]string{
				EnvIdentityBindingSNIName: "sni.example.com",
			},
			expectError: true,
		},
		{
			name: "sni with protocol prefix errors",
			env: map[string]string{
				EnvIdentityBindingSNIName:       "https://sni.example.com",
				EnvIdentityBindingAPIServerHost: "apiserver.example.com",
			},
			expectError: true,
		},
		{
			name: "valid minimal config",
			env: map[string]string{
				EnvIdentityBindingSNIName:       "sni.example.com",
				EnvIdentityBindingAPIServerHost: "apiserver.example.com",
			},
			assert: func(t *testing.T, cfg *IdentityBindingConfig) {
				if cfg.SNIName != "sni.example.com" {
					t.Errorf("unexpected SNIName: %s", cfg.SNIName)
				}
				if cfg.APIServerHost != "apiserver.example.com" {
					t.Errorf("unexpected APIServerHost: %s", cfg.APIServerHost)
				}
			},
		},
		{
			name: "valid with overrides",
			env: map[string]string{
				EnvIdentityBindingSNIName:       "sni.example.com",
				EnvIdentityBindingAPIServerHost: "10.0.0.1",
				EnvIdentityBindingTokenFile:     "/custom/token",
				EnvIdentityBindingCACertPath:    "/custom/ca.crt",
			},
			assert: func(t *testing.T, cfg *IdentityBindingConfig) {
				if cfg.TokenFilePath != "/custom/token" {
					t.Errorf("unexpected TokenFilePath: %s", cfg.TokenFilePath)
				}
				if cfg.CACertPath != "/custom/ca.crt" {
					t.Errorf("unexpected CACertPath: %s", cfg.CACertPath)
				}
			},
		},
		{
			name: "AKS webhook env fallback",
			env: map[string]string{
				EnvAKSIdentityBindingSNIName:    "sni.ests.aks",
				EnvAKSIdentityBindingTokenProxy: "https://apiserver.hcp.westus2.azmk8s.io",
				EnvAKSIdentityBindingCAFile:     "/var/run/secrets/azure/wi/ca-cert/ca.crt",
				EnvAKSFederatedTokenFile:        "/var/run/secrets/azure/wi/token/azure-identity-token",
			},
			assert: func(t *testing.T, cfg *IdentityBindingConfig) {
				if cfg.SNIName != "sni.ests.aks" {
					t.Errorf("unexpected SNIName: %s", cfg.SNIName)
				}
				if cfg.APIServerHost != "apiserver.hcp.westus2.azmk8s.io" {
					t.Errorf("unexpected APIServerHost: %s", cfg.APIServerHost)
				}
				if cfg.TokenFilePath != "/var/run/secrets/azure/wi/token/azure-identity-token" {
					t.Errorf("unexpected TokenFilePath: %s", cfg.TokenFilePath)
				}
				if cfg.CACertPath != "/var/run/secrets/azure/wi/ca-cert/ca.crt" {
					t.Errorf("unexpected CACertPath: %s", cfg.CACertPath)
				}
			},
		},
		{
			name: "ratify-specific vars take precedence over AKS fallback",
			env: map[string]string{
				EnvIdentityBindingSNIName:       "sni.override",
				EnvIdentityBindingAPIServerHost: "apiserver.override",
				EnvAKSIdentityBindingSNIName:    "sni.ests.aks",
				EnvAKSIdentityBindingTokenProxy: "https://apiserver.hcp.westus2.azmk8s.io",
			},
			assert: func(t *testing.T, cfg *IdentityBindingConfig) {
				if cfg.SNIName != "sni.override" {
					t.Errorf("unexpected SNIName: %s", cfg.SNIName)
				}
				if cfg.APIServerHost != "apiserver.override" {
					t.Errorf("unexpected APIServerHost: %s", cfg.APIServerHost)
				}
			},
		},
		{
			name: "AKS token proxy with port strips scheme and port",
			env: map[string]string{
				EnvAKSIdentityBindingSNIName:    "sni.ests.aks",
				EnvAKSIdentityBindingTokenProxy: "https://apiserver.hcp.westus2.azmk8s.io:443",
			},
			assert: func(t *testing.T, cfg *IdentityBindingConfig) {
				if cfg.APIServerHost != "apiserver.hcp.westus2.azmk8s.io" {
					t.Errorf("unexpected APIServerHost: %s", cfg.APIServerHost)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Ensure a clean slate for the identity binding env vars.
			for _, k := range []string{
				EnvIdentityBindingSNIName,
				EnvIdentityBindingAPIServerHost,
				EnvIdentityBindingTokenFile,
				EnvIdentityBindingCACertPath,
				EnvAKSIdentityBindingSNIName,
				EnvAKSIdentityBindingTokenProxy,
				EnvAKSIdentityBindingCAFile,
				EnvAKSFederatedTokenFile,
			} {
				t.Setenv(k, "")
			}
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			cfg, err := LoadIdentityBindingConfigFromEnv()
			if tt.expectError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.expectNil {
				if cfg != nil {
					t.Fatalf("expected nil config, got %+v", cfg)
				}
				return
			}
			if cfg == nil {
				t.Fatal("expected non-nil config")
			}
			if tt.assert != nil {
				tt.assert(t, cfg)
			}
		})
	}
}

func TestNewIdentityBindingCredential(t *testing.T) {
	tokenFile := writeTempFile(t, "token", "sa-token")

	tests := []struct {
		name        string
		clientID    string
		tenantID    string
		cfg         IdentityBindingConfig
		env         map[string]string
		expectError bool
	}{
		{
			name:        "missing SNI name",
			clientID:    "client",
			cfg:         IdentityBindingConfig{APIServerHost: "apiserver.example.com", TokenFilePath: tokenFile},
			expectError: true,
		},
		{
			name:        "SNI name with protocol prefix",
			clientID:    "client",
			cfg:         IdentityBindingConfig{SNIName: "https://sni.example.com", APIServerHost: "apiserver.example.com", TokenFilePath: tokenFile},
			expectError: true,
		},
		{
			name:        "missing API server host",
			clientID:    "client",
			cfg:         IdentityBindingConfig{SNIName: "sni.example.com", TokenFilePath: tokenFile},
			expectError: true,
		},
		{
			name:        "missing client ID",
			cfg:         IdentityBindingConfig{SNIName: "sni.example.com", APIServerHost: "apiserver.example.com", TokenFilePath: tokenFile},
			expectError: true,
		},
		{
			name:     "valid explicit config",
			clientID: "client",
			tenantID: "tenant",
			cfg:      IdentityBindingConfig{SNIName: "sni.example.com", APIServerHost: "apiserver.example.com", TokenFilePath: tokenFile},
		},
		{
			name: "valid using env fallback for client ID and default token path",
			cfg:  IdentityBindingConfig{SNIName: "sni.example.com", APIServerHost: "apiserver.example.com"},
			env:  map[string]string{"AZURE_CLIENT_ID": "env-client"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AZURE_CLIENT_ID", "")
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			cred, err := newIdentityBindingCredential(tt.clientID, tt.tenantID, tt.cfg)
			if tt.expectError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			ibCred, ok := cred.(*identityBindingCredential)
			if !ok {
				t.Fatalf("expected *identityBindingCredential, got %T", cred)
			}
			if ibCred.endpoint != "https://"+tt.cfg.SNIName {
				t.Errorf("expected endpoint https://%s, got %s", tt.cfg.SNIName, ibCred.endpoint)
			}
			if ibCred.caCertPath != defaultKubernetesCACertPath {
				t.Errorf("expected default CA path, got %s", ibCred.caCertPath)
			}
			if ibCred.tokenFilePath == "" {
				t.Error("expected a token file path to be set")
			}
		})
	}
}

func TestNewIdentityBindingCredential_DefaultTokenPath(t *testing.T) {
	t.Setenv("AZURE_CLIENT_ID", "")
	cred, err := newIdentityBindingCredential("client", "tenant", IdentityBindingConfig{
		SNIName:       "sni.example.com",
		APIServerHost: "apiserver.example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ibCred := cred.(*identityBindingCredential)
	if ibCred.tokenFilePath != defaultServiceAccountTokenPath {
		t.Errorf("expected default SA token path %s, got %s", defaultServiceAccountTokenPath, ibCred.tokenFilePath)
	}
}

func TestIdentityBindingCredential_GetToken_Success(t *testing.T) {
	tokenFile := writeTempFile(t, "token", "  sa-token-value  ")

	var gotForm map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = map[string]string{
			"grant_type":            r.FormValue("grant_type"),
			"client_assertion_type": r.FormValue("client_assertion_type"),
			"scope":                 r.FormValue("scope"),
			"client_assertion":      r.FormValue("client_assertion"),
			"client_id":             r.FormValue("client_id"),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "aad-access-token", ExpiresIn: 3600})
	}))
	defer server.Close()

	cred := &identityBindingCredential{
		clientID:      "my-client",
		tenantID:      "my-tenant",
		endpoint:      server.URL,
		tokenFilePath: tokenFile,
		transport:     http.DefaultTransport.(*http.Transport).Clone(),
	}

	token, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{testACRScope}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.Token != "aad-access-token" {
		t.Errorf("expected access token 'aad-access-token', got %s", token.Token)
	}
	if !token.ExpiresOn.After(time.Now()) {
		t.Errorf("expected expiry in the future, got %v", token.ExpiresOn)
	}

	if gotForm["grant_type"] != "client_credentials" {
		t.Errorf("unexpected grant_type: %s", gotForm["grant_type"])
	}
	if gotForm["client_assertion_type"] != clientAssertionType {
		t.Errorf("unexpected client_assertion_type: %s", gotForm["client_assertion_type"])
	}
	if gotForm["scope"] != testACRScope {
		t.Errorf("unexpected scope: %s", gotForm["scope"])
	}
	if gotForm["client_assertion"] != "sa-token-value" {
		t.Errorf("expected trimmed client_assertion 'sa-token-value', got %q", gotForm["client_assertion"])
	}
	if gotForm["client_id"] != "my-client" {
		t.Errorf("unexpected client_id: %s", gotForm["client_id"])
	}
}

func TestIdentityBindingCredential_GetToken_Errors(t *testing.T) {
	tokenFile := writeTempFile(t, "token", "sa-token")

	t.Run("wrong scope count", func(t *testing.T) {
		cred := &identityBindingCredential{tokenFilePath: tokenFile, transport: http.DefaultTransport.(*http.Transport).Clone()}
		if _, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{"a", "b"}}); err == nil {
			t.Fatal("expected error for multiple scopes")
		}
	})

	t.Run("missing token file", func(t *testing.T) {
		cred := &identityBindingCredential{tokenFilePath: filepath.Join(t.TempDir(), "does-not-exist"), transport: http.DefaultTransport.(*http.Transport).Clone()}
		if _, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{testACRScope}}); err == nil {
			t.Fatal("expected error for missing token file")
		}
	})

	t.Run("empty token file", func(t *testing.T) {
		empty := writeTempFile(t, "empty", "")
		cred := &identityBindingCredential{tokenFilePath: empty, transport: http.DefaultTransport.(*http.Transport).Clone()}
		if _, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{testACRScope}}); err == nil {
			t.Fatal("expected error for empty token file")
		}
	})

	t.Run("non-200 response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("denied"))
		}))
		defer server.Close()
		cred := &identityBindingCredential{clientID: "c", endpoint: server.URL, tokenFilePath: tokenFile, transport: http.DefaultTransport.(*http.Transport).Clone()}
		if _, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{testACRScope}}); err == nil {
			t.Fatal("expected error for non-200 response")
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not-json"))
		}))
		defer server.Close()
		cred := &identityBindingCredential{clientID: "c", endpoint: server.URL, tokenFilePath: tokenFile, transport: http.DefaultTransport.(*http.Transport).Clone()}
		if _, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{testACRScope}}); err == nil {
			t.Fatal("expected error for invalid json")
		}
	})

	t.Run("empty access token", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(tokenResponse{ExpiresIn: 3600})
		}))
		defer server.Close()
		cred := &identityBindingCredential{clientID: "c", endpoint: server.URL, tokenFilePath: tokenFile, transport: http.DefaultTransport.(*http.Transport).Clone()}
		if _, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{testACRScope}}); err == nil {
			t.Fatal("expected error for empty access token")
		}
	})
}

func TestIdentityBindingCredential_GetTransport(t *testing.T) {
	caPEM := generateTestCACert(t)

	t.Run("valid CA", func(t *testing.T) {
		caFile := writeTempFile(t, "ca.crt", caPEM)
		cred := &identityBindingCredential{sniName: "sni.example.com", apiServerHost: "apiserver.example.com", caCertPath: caFile}
		transport, err := cred.getTransport()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if transport.TLSClientConfig.ServerName != "sni.example.com" {
			t.Errorf("expected ServerName sni.example.com, got %s", transport.TLSClientConfig.ServerName)
		}
		if transport.TLSClientConfig.RootCAs == nil {
			t.Error("expected RootCAs to be set")
		}
		if transport.Proxy != nil {
			t.Error("expected Proxy to be nil")
		}
		transport2, err := cred.getTransport()
		if err != nil || transport2 != transport {
			t.Error("expected cached transport on second call")
		}
	})

	t.Run("missing CA file", func(t *testing.T) {
		cred := &identityBindingCredential{caCertPath: filepath.Join(t.TempDir(), "missing")}
		if _, err := cred.getTransport(); err == nil {
			t.Fatal("expected error for missing CA file")
		}
	})

	t.Run("invalid CA content", func(t *testing.T) {
		bad := writeTempFile(t, "bad.crt", "not a cert")
		cred := &identityBindingCredential{caCertPath: bad}
		if _, err := cred.getTransport(); err == nil {
			t.Fatal("expected error for invalid CA content")
		}
	})
}

func TestCreateCredentialChainWithIdentityBinding(t *testing.T) {
	tokenFile := writeTempFile(t, "token", "sa-token")

	t.Run("nil identity binding config", func(t *testing.T) {
		cred, err := CreateCredentialChainWithIdentityBinding("client", "tenant", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred == nil {
			t.Fatal("expected non-nil credential")
		}
	})

	t.Run("valid identity binding config", func(t *testing.T) {
		cred, err := CreateCredentialChainWithIdentityBinding("client", "tenant", &IdentityBindingConfig{
			SNIName:       "sni.example.com",
			APIServerHost: "apiserver.example.com",
			TokenFilePath: tokenFile,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred == nil {
			t.Fatal("expected non-nil credential")
		}
	})

	t.Run("invalid identity binding config", func(t *testing.T) {
		_, err := CreateCredentialChainWithIdentityBinding("client", "tenant", &IdentityBindingConfig{
			SNIName:       "sni.example.com",
			TokenFilePath: tokenFile,
			// APIServerHost missing
		})
		if err == nil {
			t.Fatal("expected error for invalid identity binding config")
		}
	})
}

// generateTestCACert returns a self-signed CA certificate in PEM format.
func generateTestCACert(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
