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

package filesystemprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/notaryproject/ratify/v2/internal/verifier/keyprovider"
)

type contextKey string

const (
	symDataPath             = "..data"
	realDataPath            = "..real-data"
	certFileName            = "cert.pem"
	testKey      contextKey = "key"
)

func TestInit(t *testing.T) {
	if _, err := keyprovider.CreateKeyProvider(fileSystemProviderName, make(chan int)); err == nil {
		t.Fatalf("expected error, got nil")
	}

	if _, err := keyprovider.CreateKeyProvider(fileSystemProviderName, "{"); err == nil {
		t.Fatalf("expected error, got nil")
	}

	if _, err := keyprovider.CreateKeyProvider(fileSystemProviderName, []string{}); err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestGetCertificates(t *testing.T) {
	tempDir := t.TempDir()

	if err := os.Mkdir(filepath.Join(tempDir, realDataPath), 0755); err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	if err := os.Symlink(filepath.Join(tempDir, realDataPath), filepath.Join(tempDir, symDataPath)); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	// Create a temporary certificate file.
	certFile := filepath.Join(tempDir, realDataPath, certFileName)
	certContent, err := createCert()
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	if err := os.WriteFile(certFile, certContent, 0600); err != nil {
		t.Fatalf("failed to create temp cert file: %v", err)
	}

	// Create a symlink to the certificate file.
	certFileSymLink := filepath.Join(tempDir, certFileName)
	if err := os.Symlink(certFile, certFileSymLink); err != nil {
		t.Fatalf("failed to create symlink for cert file: %v", err)
	}

	// Successfully create a key provider with the symlinked directory.
	opts := []string{tempDir}
	provider, err := keyprovider.CreateKeyProvider(fileSystemProviderName, opts)
	if err != nil {
		t.Fatalf("failed to create key provider: %v", err)
	}
	certs, err := provider.GetCertificates(context.Background())
	if err != nil {
		t.Fatalf("failed to get certificates: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected at least one certificate, got %d", len(certs))
	}

	// Create a broken symlink.
	brokenSymlink := filepath.Join(tempDir, "broken-symlink")
	if err := os.Symlink("nonexistent-file", brokenSymlink); err != nil {
		t.Fatalf("failed to create broken symlink: %v", err)
	}
	certs, err = provider.GetCertificates(context.Background())
	if err != nil {
		t.Fatalf("failed to get certificates: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected at least one certificate, got %d", len(certs))
	}

	// Loading an invalid certificate should fail during provider creation.
	invalidCertFile := filepath.Join(tempDir, realDataPath, "invalid-cert.pem")
	if err := os.WriteFile(invalidCertFile, []byte("invalid cert content"), 0600); err != nil {
		t.Fatalf("failed to create invalid cert file: %v", err)
	}

	// Create a new provider with the directory containing invalid certificate
	optsWithInvalid := []string{tempDir}
	_, err = keyprovider.CreateKeyProvider(fileSystemProviderName, optsWithInvalid)
	if err == nil {
		t.Fatalf("expected error while loading invalid certificate during provider creation, got nil")
	}
}

func TestGetCertificatesFromCache(t *testing.T) {
	tempDir := t.TempDir()

	// Create a temporary certificate file.
	certFile := filepath.Join(tempDir, "test-cert.pem")
	certContent, err := createCert()
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	if err := os.WriteFile(certFile, certContent, 0600); err != nil {
		t.Fatalf("failed to create temp cert file: %v", err)
	}

	// Create provider which should load certificates during initialization
	opts := []string{tempDir}
	provider, err := keyprovider.CreateKeyProvider(fileSystemProviderName, opts)
	if err != nil {
		t.Fatalf("failed to create key provider: %v", err)
	}

	// Get certificates first time
	certs1, err := provider.GetCertificates(context.Background())
	if err != nil {
		t.Fatalf("failed to get certificates: %v", err)
	}
	if len(certs1) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(certs1))
	}

	// Remove the certificate file to ensure we're getting from cache
	if err := os.Remove(certFile); err != nil {
		t.Fatalf("failed to remove cert file: %v", err)
	}

	// Get certificates second time - should still work from cache
	certs2, err := provider.GetCertificates(context.Background())
	if err != nil {
		t.Fatalf("failed to get certificates from cache: %v", err)
	}
	if len(certs2) != 1 {
		t.Fatalf("expected 1 cached certificate, got %d", len(certs2))
	}

	// Verify both calls return the same certificate
	if !certs1[0].Equal(certs2[0]) {
		t.Fatalf("cached certificate doesn't match original")
	}
}

func TestGetKeys(t *testing.T) {
	tests := []struct {
		name          string
		setupProvider func(t *testing.T) keyprovider.KeyProvider
		expectError   bool
		errorMsg      string
	}{
		{
			name: "GetKeys not implemented - provider with certificates",
			setupProvider: func(t *testing.T) keyprovider.KeyProvider {
				tempDir := t.TempDir()

				// Create a temporary certificate file
				certFile := filepath.Join(tempDir, "test-cert.pem")
				certContent, err := createCert()
				if err != nil {
					t.Fatalf("failed to create certificate: %v", err)
				}
				if err := os.WriteFile(certFile, certContent, 0600); err != nil {
					t.Fatalf("failed to create temp cert file: %v", err)
				}

				opts := []string{tempDir}
				provider, err := keyprovider.CreateKeyProvider(fileSystemProviderName, opts)
				if err != nil {
					t.Fatalf("failed to create key provider: %v", err)
				}
				return provider
			},
			expectError: true,
			errorMsg:    "GetKeys not implemented in FileSystemProvider",
		},
		{
			name: "GetKeys not implemented - empty provider",
			setupProvider: func(t *testing.T) keyprovider.KeyProvider {
				tempDir := t.TempDir()
				opts := []string{tempDir}
				provider, err := keyprovider.CreateKeyProvider(fileSystemProviderName, opts)
				if err != nil {
					t.Fatalf("failed to create key provider: %v", err)
				}
				return provider
			},
			expectError: true,
			errorMsg:    "GetKeys not implemented in FileSystemProvider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := tt.setupProvider(t)

			keys, err := provider.GetKeys(context.Background())

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if err.Error() != tt.errorMsg {
					t.Fatalf("expected error message '%s', got '%s'", tt.errorMsg, err.Error())
				}
				if keys != nil {
					t.Fatalf("expected nil keys when error occurs, got %v", keys)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if keys == nil {
					t.Fatalf("expected non-nil keys slice, got nil")
				}
			}
		})
	}
}

func TestGetKeysWithContext(t *testing.T) {
	tempDir := t.TempDir()

	// Create a temporary certificate file
	certFile := filepath.Join(tempDir, "test-cert.pem")
	certContent, err := createCert()
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	if err := os.WriteFile(certFile, certContent, 0600); err != nil {
		t.Fatalf("failed to create temp cert file: %v", err)
	}

	opts := []string{tempDir}
	provider, err := keyprovider.CreateKeyProvider(fileSystemProviderName, opts)
	if err != nil {
		t.Fatalf("failed to create key provider: %v", err)
	}

	tests := []struct {
		name string
		ctx  context.Context
	}{
		{
			name: "GetKeys with background context",
			ctx:  context.Background(),
		},
		{
			name: "GetKeys with TODO context",
			ctx:  context.TODO(),
		},
		{
			name: "GetKeys with value context",
			ctx:  context.WithValue(context.Background(), testKey, "value"),
		},
		{
			name: "GetKeys with cancelled context",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, err := provider.GetKeys(tt.ctx)

			// All contexts should return the same error since GetKeys is not implemented
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if err.Error() != "GetKeys not implemented in FileSystemProvider" {
				t.Fatalf("expected 'GetKeys not implemented in FileSystemProvider' error, got '%s'", err.Error())
			}
			if keys != nil {
				t.Fatalf("expected nil keys when error occurs, got %v", keys)
			}
		})
	}
}

func createCert() ([]byte, error) {
	// Generate a private key first (needed for signing)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Create a certificate template
	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"My Company, Inc."},
			Country:       []string{"US"},
			Province:      []string{"California"},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Market Street"},
			PostalCode:    []string{"94103"},
			CommonName:    "example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Self-sign the certificate (for demonstration)
	return x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &priv.PublicKey, priv)
}
