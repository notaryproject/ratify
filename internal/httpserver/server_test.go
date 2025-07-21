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

package httpserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify/v2/internal/executor"
	"github.com/notaryproject/ratify/v2/internal/store"
	"github.com/notaryproject/ratify/v2/internal/verifier"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	invalidConfigPath = "/invalid/path"
	registryPattern   = "registry.pattern"
	mockStoreType     = "mock-store-type"
	artifact1         = "test.registry.io/test/image1:v1"
)

func createMockVerifier(*verifier.NewOptions, []string) (ratify.Verifier, error) {
	return &mockVerifier{}, nil
}

type mockStore struct {
	resolveMap       map[string]ocispec.Descriptor
	returnResolveErr bool
}

func (m *mockStore) Resolve(_ context.Context, ref string) (ocispec.Descriptor, error) {
	if m.returnResolveErr {
		return ocispec.Descriptor{}, fmt.Errorf("mock error")
	}
	if m.resolveMap != nil {
		if desc, ok := m.resolveMap[ref]; ok {
			return desc, nil
		}
	}
	return ocispec.Descriptor{}, nil
}

func (m *mockStore) ListReferrers(_ context.Context, _ string, _ []string, _ func(referrers []ocispec.Descriptor) error) error {
	return nil
}

func (m *mockStore) FetchBlob(_ context.Context, _ string, _ ocispec.Descriptor) ([]byte, error) {
	return nil, nil
}

func (m *mockStore) FetchManifest(_ context.Context, _ string, _ ocispec.Descriptor) ([]byte, error) {
	return nil, nil
}

func newMockStore(_ *store.NewOptions) (ratify.Store, error) {
	return &mockStore{}, nil
}

func init() {
	verifier.RegisterVerifierFactory(mockVerifierType, createMockVerifier)
	store.RegisterStoreFactory(mockStoreType, newMockStore)
}

func TestStartServer(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name          string
		serverOpts    *ServerOptions
		executorOpts  *executor.Options
		configPath    string
		expectedError bool
	}{
		{
			name: "Invalid config path",
			serverOpts: &ServerOptions{
				DisableCRDManager: true,
			},
			executorOpts:  &executor.Options{},
			configPath:    invalidConfigPath,
			expectedError: true,
		},
		{
			name: "Failed to create the executor",
			serverOpts: &ServerOptions{
				DisableCRDManager: true,
			},
			executorOpts:  &executor.Options{},
			configPath:    filepath.Join(tempDir, "config.json"),
			expectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.configPath != invalidConfigPath {
				raw, err := json.Marshal(test.executorOpts)
				if err != nil {
					t.Fatalf("failed to marshal executor options: %v", err)
				}
				if err := os.WriteFile(test.configPath, raw, 0600); err != nil {
					t.Fatalf("failed to write config file: %v", err)
				}
			}

			err := StartServer(test.serverOpts, test.configPath)
			if (err != nil) != test.expectedError {
				t.Errorf("expected error: %v, got: %v", test.expectedError, err)
			}
		})
	}
}

func TestStartServer_NoTLS(t *testing.T) {
	tempDir := t.TempDir()

	executorOpts := &executor.Options{
		Executors: []*executor.ScopedOptions{
			{
				Scopes: []string{registryPattern},
				Verifiers: []*verifier.NewOptions{
					{
						Name: mockVerifierName,
						Type: mockVerifierType,
					},
				},
				Stores: []*store.NewOptions{
					{
						Type: mockStoreType,
					},
				},
			},
		},
	}

	raw, err := json.Marshal(executorOpts)
	if err != nil {
		t.Fatalf("failed to marshal executor options: %v", err)
	}
	configPath := filepath.Join(tempDir, "config.json")
	if err := os.WriteFile(configPath, raw, 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}
	serverOpts := &ServerOptions{
		HTTPServerAddress: ":8080",
	}

	errChan := make(chan error)
	go func() {
		errChan <- StartServer(serverOpts, configPath)
	}()

	time.Sleep(1 * time.Second)
	p, _ := os.FindProcess(os.Getpid())
	if err = p.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("failed to send SIGTERM: %v", err)
	}

	if err := <-errChan; err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
}

func TestStartServer_TLSEnabled(t *testing.T) {
	tempDir := t.TempDir()

	executorOpts := &executor.Options{
		Executors: []*executor.ScopedOptions{
			{
				Scopes: []string{registryPattern},
				Verifiers: []*verifier.NewOptions{
					{
						Name: mockVerifierName,
						Type: mockVerifierType,
					},
				},
				Stores: []*store.NewOptions{
					{
						Type: mockStoreType,
					},
				},
			},
		},
	}

	raw, err := json.Marshal(executorOpts)
	if err != nil {
		t.Fatalf("failed to marshal executor options: %v", err)
	}
	configPath := filepath.Join(tempDir, "config.json")
	if err := os.WriteFile(configPath, raw, 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	certPath, keyPath, err := createTLSCertAndKey(tempDir)
	if err != nil {
		t.Fatalf("failed to create TLS cert and key: %v", err)
	}
	serverOpts := &ServerOptions{
		HTTPServerAddress: ":8080",
		CertFile:          certPath,
		KeyFile:           keyPath,
	}

	errChan := make(chan error)
	go func() {
		errChan <- StartServer(serverOpts, configPath)
	}()

	time.Sleep(1 * time.Second)
	p, _ := os.FindProcess(os.Getpid())
	if err = p.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("failed to send SIGTERM: %v", err)
	}

	if err := <-errChan; err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
}

func TestStartServer_InvalidTLS(t *testing.T) {
	tempDir := t.TempDir()

	executorOpts := &executor.Options{
		Executors: []*executor.ScopedOptions{
			{
				Scopes: []string{registryPattern},
				Verifiers: []*verifier.NewOptions{
					{
						Name: mockVerifierName,
						Type: mockVerifierType,
					},
				},
				Stores: []*store.NewOptions{
					{
						Type: mockStoreType,
					},
				},
			},
		},
	}

	raw, err := json.Marshal(executorOpts)
	if err != nil {
		t.Fatalf("failed to marshal executor options: %v", err)
	}
	configPath := filepath.Join(tempDir, "config.json")
	if err := os.WriteFile(configPath, raw, 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	serverOpts := &ServerOptions{
		HTTPServerAddress: ":8080",
		CertFile:          "invalid/path/to/cert.pem",
		KeyFile:           "invalid/path/to/key.pem",
	}

	errChan := make(chan error)
	go func() {
		errChan <- StartServer(serverOpts, configPath)
	}()

	time.Sleep(1 * time.Second)
	p, _ := os.FindProcess(os.Getpid())
	if err = p.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("failed to send SIGTERM: %v", err)
	}

	if err := <-errChan; err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
}

func createTLSCertAndKey(dir string) (string, string, error) {
	// 1. Generate a private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Errorf("failed to generate private key: %w", err))
	}

	// 2. Create a certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"Example Org"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(1 * time.Hour), // valid for 1 year

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// 3. Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		panic(fmt.Errorf("failed to create certificate: %w", err))
	}

	// 4. Encode and save the certificate to cert.pem
	certPath := filepath.Join(dir, "cert.pem")
	certOut, err := os.Create(certPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to open cert.pem for writing: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return "", "", fmt.Errorf("failed to write data to cert.pem: %w", err)
	}

	// 5. Encode and save the private key to key.pem
	keyPath := filepath.Join(dir, "key.pem")
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to open key.pem for writing: %w", err)
	}
	defer keyOut.Close()

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		return "", "", fmt.Errorf("failed to write data to key.pem: %w", err)
	}

	return certPath, keyPath, nil
}
