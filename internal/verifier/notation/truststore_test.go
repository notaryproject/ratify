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

package notation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/notaryproject/notation-go/verifier/truststore"
	"github.com/notaryproject/ratify/v2/internal/verifier/keyprovider"
)

const (
	storeName1 = "store1"
	storeName2 = "store2"
)

// testKeyProvider is a test implementation of keyprovider.KeyProvider for testing
type testKeyProvider struct {
	certificates []*x509.Certificate
	error        error
}

func (t *testKeyProvider) GetCertificates(_ context.Context) ([]*x509.Certificate, error) {
	if t.error != nil {
		return nil, t.error
	}
	return t.certificates, nil
}

func (t *testKeyProvider) GetKeys(_ context.Context) ([]*keyprovider.PublicKey, error) {
	return nil, nil
}

func generateTestCACertificate(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}

func generateTestLeafCertificate(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano() + 1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}

func TestTrustStore(t *testing.T) {
	trustStore := newTrustStore()

	cert1 := generateTestCACertificate(t, "cert1")
	cert2 := generateTestCACertificate(t, "cert2")

	// Create a test key provider with the certificates
	keyProvider := &testKeyProvider{
		certificates: []*x509.Certificate{cert1, cert2},
	}

	trustStore.addKeyProvider(truststore.TypeCA, storeName1, keyProvider)

	certs, err := trustStore.GetCertificates(context.Background(), truststore.TypeCA, storeName1)
	if err != nil {
		t.Fatalf("failed to get certificates: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(certs))
	}

	certs, err = trustStore.GetCertificates(context.Background(), truststore.TypeCA, storeName2)
	if err != nil {
		t.Fatalf("failed to get certificates: %v", err)
	}
	if certs != nil {
		t.Fatalf("expected no certificates, got %d", len(certs))
	}
}

func TestTrustStoreMultipleKeyProviders(t *testing.T) {
	trustStore := newTrustStore()

	cert1 := generateTestCACertificate(t, "cert1")
	cert2 := generateTestCACertificate(t, "cert2")
	cert3 := generateTestCACertificate(t, "cert3")

	// Create two key providers
	keyProvider1 := &testKeyProvider{
		certificates: []*x509.Certificate{cert1, cert2},
	}
	keyProvider2 := &testKeyProvider{
		certificates: []*x509.Certificate{cert3},
	}

	// Add both key providers to the same store
	trustStore.addKeyProvider(truststore.TypeCA, storeName1, keyProvider1)
	trustStore.addKeyProvider(truststore.TypeCA, storeName1, keyProvider2)

	certs, err := trustStore.GetCertificates(context.Background(), truststore.TypeCA, storeName1)
	if err != nil {
		t.Fatalf("failed to get certificates: %v", err)
	}

	// Should get all 3 certificates from both providers
	if len(certs) != 3 {
		t.Fatalf("expected 3 certificates, got %d", len(certs))
	}

	// Verify we got the right certificates
	commonNames := make(map[string]bool)
	for _, cert := range certs {
		commonNames[cert.Subject.CommonName] = true
	}

	expectedNames := []string{"cert1", "cert2", "cert3"}
	for _, name := range expectedNames {
		if !commonNames[name] {
			t.Errorf("expected certificate with common name %s", name)
		}
	}
}

func TestTrustStoreReturnsLeafCertificate(t *testing.T) {
	trustStore := newTrustStore()
	leafCert := generateTestLeafCertificate(t, "leaf")
	keyProvider := &testKeyProvider{
		certificates: []*x509.Certificate{leafCert},
	}

	trustStore.addKeyProvider(truststore.TypeCA, storeName1, keyProvider)

	certs, err := trustStore.GetCertificates(context.Background(), truststore.TypeCA, storeName1)
	if err != nil {
		t.Fatalf("failed to get certificates: %v", err)
	}
	if len(certs) != 1 || !certs[0].Equal(leafCert) {
		t.Fatal("expected trust store to return the leaf certificate")
	}
}

func TestTrustStoreKeyProviderError(t *testing.T) {
	trustStore := newTrustStore()

	// Create a key provider that returns an error
	keyProvider := &testKeyProvider{
		error: fmt.Errorf("test error"),
	}

	trustStore.addKeyProvider(truststore.TypeCA, storeName1, keyProvider)

	_, err := trustStore.GetCertificates(context.Background(), truststore.TypeCA, storeName1)
	if err == nil {
		t.Fatal("expected error but got none")
	}

	if err.Error() != "test error" {
		t.Fatalf("expected 'test error', got '%v'", err)
	}
}

func TestTrustStoreEmptyKeyProvider(t *testing.T) {
	trustStore := newTrustStore()

	// Create a key provider with no certificates
	keyProvider := &testKeyProvider{
		certificates: []*x509.Certificate{},
	}

	trustStore.addKeyProvider(truststore.TypeCA, storeName1, keyProvider)

	certs, err := trustStore.GetCertificates(context.Background(), truststore.TypeCA, storeName1)
	if err != nil {
		t.Fatalf("failed to get certificates: %v", err)
	}

	if len(certs) != 0 {
		t.Fatalf("expected 0 certificates, got %d", len(certs))
	}
}
