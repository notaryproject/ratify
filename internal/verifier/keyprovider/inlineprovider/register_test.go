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

package inlineprovider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/notaryproject/ratify/v2/internal/verifier/keyprovider"
)

const invalidCert = "-----BEGIN CERTIFICATE-----\nMIID2jCCAsKgAwIBAgIQXy2VqtlhSkiZKAGhsnkjbDANBgkqhkiG9w0BAQsFADBvMRswGQYDVQQD\nExJyYXRpZnkuZXhhbXBsZS5jb20xDzANBgNVBAsTBk15IE9yZzETMBEGA1UEChMKTXkgQ29tcGFu\neTEQMA4GA1UEBxMHUmVkbW9uZDELMAkGA1UECBMCV0ExCzAJBgNVBAYTAlVTMB4XDTIzMDIwMTIy\nNDUwMFoXDTI0MDIwMTIyNTUwMFowbzEbMBkGA1UEAxMScmF0aWZ5LmV4YW1wbGUuY29tMQ8wDQYD\nVQQLEwZNeSBPcmcxEzARBgNVBAoTCk15IENvbXBhbnkxEDAOBgNVBAcTB1JlZG1vbmQxCzAJBgNV\nBAgTAldBMQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL10bM81\npPAyuraORABsOGS8M76Bi7Guwa3JlM1g2D8CuzSfSTaaT6apy9GsccxUvXd5cmiP1ffna5z+EFmc\nizFQh2aq9kWKWXDvKFXzpQuhyqD1HeVlRlF+V0AfZPvGt3VwUUjNycoUU44ctCWmcUQP/KShZev3\n6SOsJ9q7KLjxxQLsUc4mg55eZUThu8mGB8jugtjsnLUYvIWfHhyjVpGrGVrdkDMoMn+u33scOmrt\nsBljvq9WVo4T/VrTDuiOYlAJFMUae2Ptvo0go8XTN3OjLblKeiK4C+jMn9Dk33oGIT9pmX0vrDJV\nX56w/2SejC1AxCPchHaMuhlwMpftBGkCAwEAAaNyMHAwDgYDVR0PAQH/BAQDAgeAMAkGA1UdEwQC\nMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHwYDVR0jBBgwFoAU0eaKkZj+MS9jCp9Dg1zdv3v/aKww\nHQYDVR0OBBYEFNHmipGY/jEvYwqfQ4Nc3b97/2isMA0GCSqGSIb3DQEBCwUAA4IBAQBNDcmSBizF\nmpJlD8EgNcUCy5tz7W3+AAhEbA3vsHP4D/UyV3UgcESx+L+Nye5uDYtTVm3lQejs3erN2BjW+ds+\nXFnpU/pVimd0aYv6mJfOieRILBF4XFomjhrJOLI55oVwLN/AgX6kuC3CJY2NMyJKlTao9oZgpHhs\nLlxB/r0n9JnUoN0Gq93oc1+OLFjPI7gNuPXYOP1N46oKgEmAEmNkP1etFrEjFRgsdIFHksrmlOlD\nIed9RcQ087VLjmuymLgqMTFX34Q3j7XgN2ENwBSnkHotE9CcuGRW+NuiOeJalL8DBmFXXWwHTKLQ\nPp5g6m1yZXylLJaFLKz7tdMmO355invalid\n-----END CERTIFICATE-----\n"

// generateSelfSignedPEM creates a one–off self-signed x509 certificate and
// returns its PEM encoding together with the parsed certificate.
func generateSelfSignedPEM(t *testing.T) (string, *x509.Certificate) {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),

		Subject: pkix.Name{
			CommonName: "ratify-unit-test",
		},

		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}
	return string(pemBytes), cert
}

// generateRSAPublicKeyPEM creates a RSA public key and returns its PEM encoding
func generateRSAPublicKeyPEM(t *testing.T) (string, *rsa.PublicKey) {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})
	return string(pemBytes), &privKey.PublicKey
}

// generateRSAPublicKeyPKCS1PEM creates a RSA public key in PKCS1 format and returns its PEM encoding
func generateRSAPublicKeyPKCS1PEM(t *testing.T) (string, *rsa.PublicKey) {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	pubKeyBytes := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubKeyBytes})
	return string(pemBytes), &privKey.PublicKey
}

// generateECPublicKeyPEM creates an EC public key and returns its PEM encoding
func generateECPublicKeyPEM(t *testing.T) (string, *ecdsa.PublicKey) {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal EC public key: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PUBLIC KEY", Bytes: pubKeyBytes})
	return string(pemBytes), &privKey.PublicKey
}

// generateInvalidPEMData creates a PEM block with invalid data for testing error cases
func generateInvalidPEMData(blockType string) string {
	// Generate base64 encoded "invalid key data" to avoid hardcoding secrets
	invalidData := "aW52YWxpZCBrZXkgZGF0YQ=="
	return fmt.Sprintf(`-----BEGIN %s-----
%s
-----END %s-----`, blockType, invalidData, blockType)
}

func TestInlineProvider_CertificatesSuccess(t *testing.T) {
	pemStr, wantCert := generateSelfSignedPEM(t)

	// The inline provider is registered in init(). Retrieve it through the
	// keyprovider registry.
	provider, err := keyprovider.CreateKeyProvider("inline", map[string]interface{}{
		"certs": pemStr,
	})
	if err != nil {
		t.Fatalf("unexpected error constructing provider: %v", err)
	}

	got, err := provider.GetCertificates(context.Background())
	if err != nil {
		t.Fatalf("unexpected error retrieving certificates: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(got))
	}
	if !got[0].Equal(wantCert) {
		t.Fatalf("returned certificate does not match the provided one")
	}

	// Test GetKeys returns empty for certs-only provider
	keys, err := provider.GetKeys(context.Background())
	if err != nil {
		t.Fatalf("unexpected error retrieving keys: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(keys))
	}
}

func TestInlineProvider_KeysSuccess(t *testing.T) {
	pemStr, wantKey := generateRSAPublicKeyPEM(t)

	provider, err := keyprovider.CreateKeyProvider("inline", map[string]interface{}{
		"keys": pemStr,
	})
	if err != nil {
		t.Fatalf("unexpected error constructing provider: %v", err)
	}

	keys, err := provider.GetKeys(context.Background())
	if err != nil {
		t.Fatalf("unexpected error retrieving keys: %v", err)
	}

	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	gotKey, ok := keys[0].Key.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected RSA public key, got %T", keys[0].Key)
	}

	if gotKey.N.Cmp(wantKey.N) != 0 || gotKey.E != wantKey.E {
		t.Fatalf("returned key does not match the provided one")
	}

	// Test GetCertificates returns empty for keys-only provider
	certs, err := provider.GetCertificates(context.Background())
	if err != nil {
		t.Fatalf("unexpected error retrieving certificates: %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("expected 0 certificates, got %d", len(certs))
	}
}

func TestInlineProvider_BothCertsAndKeys(t *testing.T) {
	certPem, wantCert := generateSelfSignedPEM(t)
	keyPem, wantKey := generateRSAPublicKeyPEM(t)

	provider, err := keyprovider.CreateKeyProvider("inline", map[string]interface{}{
		"certs": certPem,
		"keys":  keyPem,
	})
	if err != nil {
		t.Fatalf("unexpected error constructing provider: %v", err)
	}

	// Test certificates
	certs, err := provider.GetCertificates(context.Background())
	if err != nil {
		t.Fatalf("unexpected error retrieving certificates: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(certs))
	}
	if !certs[0].Equal(wantCert) {
		t.Fatalf("returned certificate does not match the provided one")
	}

	// Test keys
	keys, err := provider.GetKeys(context.Background())
	if err != nil {
		t.Fatalf("unexpected error retrieving keys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	gotKey, ok := keys[0].Key.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected RSA public key, got %T", keys[0].Key)
	}

	if gotKey.N.Cmp(wantKey.N) != 0 || gotKey.E != wantKey.E {
		t.Fatalf("returned key does not match the provided one")
	}
}

func TestInlineProvider_MultipleCertificates(t *testing.T) {
	pemStr1, wantCert1 := generateSelfSignedPEM(t)
	pemStr2, wantCert2 := generateSelfSignedPEM(t)
	combinedPem := pemStr1 + "\n" + pemStr2

	provider, err := keyprovider.CreateKeyProvider("inline", map[string]interface{}{
		"certs": combinedPem,
	})
	if err != nil {
		t.Fatalf("unexpected error constructing provider: %v", err)
	}

	got, err := provider.GetCertificates(context.Background())
	if err != nil {
		t.Fatalf("unexpected error retrieving certificates: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(got))
	}

	if !got[0].Equal(wantCert1) || !got[1].Equal(wantCert2) {
		t.Fatalf("returned certificates do not match the provided ones")
	}
}

func TestInlineProvider_MultipleKeys(t *testing.T) {
	rsaPem, rsaKey := generateRSAPublicKeyPEM(t)
	rsaPKCS1Pem, rsaPKCS1Key := generateRSAPublicKeyPKCS1PEM(t)
	ecPem, ecKey := generateECPublicKeyPEM(t)
	combinedPem := rsaPem + "\n" + rsaPKCS1Pem + "\n" + ecPem

	provider, err := keyprovider.CreateKeyProvider("inline", map[string]interface{}{
		"keys": combinedPem,
	})
	if err != nil {
		t.Fatalf("unexpected error constructing provider: %v", err)
	}

	keys, err := provider.GetKeys(context.Background())
	if err != nil {
		t.Fatalf("unexpected error retrieving keys: %v", err)
	}

	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}

	// Check RSA key
	gotRSAKey, ok := keys[0].Key.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected RSA public key at index 0, got %T", keys[0].Key)
	}
	if gotRSAKey.N.Cmp(rsaKey.N) != 0 || gotRSAKey.E != rsaKey.E {
		t.Fatalf("returned RSA key does not match the provided one")
	}

	// Check RSA PKCS1 key
	gotRSAPKCS1Key, ok := keys[1].Key.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected RSA public key at index 1, got %T", keys[1].Key)
	}
	if gotRSAPKCS1Key.N.Cmp(rsaPKCS1Key.N) != 0 || gotRSAPKCS1Key.E != rsaPKCS1Key.E {
		t.Fatalf("returned RSA PKCS1 key does not match the provided one")
	}

	// Check EC key
	gotECKey, ok := keys[2].Key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected ECDSA public key at index 2, got %T", keys[2].Key)
	}
	if gotECKey.X.Cmp(ecKey.X) != 0 || gotECKey.Y.Cmp(ecKey.Y) != 0 {
		t.Fatalf("returned EC key does not match the provided one")
	}
}

func TestInlineProvider_EmptyOptions(t *testing.T) {
	provider, err := keyprovider.CreateKeyProvider("inline", map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error constructing provider with empty options: %v", err)
	}

	// Test empty certificates
	certs, err := provider.GetCertificates(context.Background())
	if err != nil {
		t.Fatalf("unexpected error retrieving certificates: %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("expected 0 certificates, got %d", len(certs))
	}

	// Test empty keys
	keys, err := provider.GetKeys(context.Background())
	if err != nil {
		t.Fatalf("unexpected error retrieving keys: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(keys))
	}
}

func TestInlineProvider_OneValidAndOneInvalidCertificate(t *testing.T) {
	pemStr, _ := generateSelfSignedPEM(t)
	pemStr += "\n" + invalidCert // Append an invalid certificate

	_, err := keyprovider.CreateKeyProvider("inline", map[string]interface{}{
		"certs": pemStr,
	})
	if err == nil {
		t.Fatalf("expected error constructing provider with invalid certificate")
	}
}

func TestInlineProvider_ParseInvalidCertificate(t *testing.T) {
	_, err := keyprovider.CreateKeyProvider("inline", map[string]interface{}{
		"certs": invalidCert,
	})
	if err == nil {
		t.Fatalf("expected error when constructing provider with invalid certificate")
	}
}

func TestInlineProvider_ParseEmptyCertificatesString(t *testing.T) {
	_, err := keyprovider.CreateKeyProvider("inline", map[string]interface{}{
		"certs": "",
	})
	if err != nil {
		t.Fatalf("unexpected error when constructing provider with empty certificates string: %v", err)
	}
}

func TestInlineProvider_ParseEmptyKeysString(t *testing.T) {
	_, err := keyprovider.CreateKeyProvider("inline", map[string]interface{}{
		"keys": "",
	})
	if err != nil {
		t.Fatalf("unexpected error when constructing provider with empty keys string: %v", err)
	}
}

func TestInlineProvider_NoCertificatesInPEM(t *testing.T) {
	// PEM block with wrong type
	pemData := generateInvalidPEMData("PRIVATE KEY")

	_, err := keyprovider.CreateKeyProvider("inline", map[string]interface{}{
		"certs": pemData,
	})
	if err == nil {
		t.Fatalf("expected error when no certificates found in PEM")
	}
}

func TestInlineProvider_NoKeysInPEM(t *testing.T) {
	// PEM block with wrong type
	pemData := generateInvalidPEMData("CERTIFICATE")

	_, err := keyprovider.CreateKeyProvider("inline", map[string]interface{}{
		"keys": pemData,
	})
	if err == nil {
		t.Fatalf("expected error when no keys found in PEM")
	}
}

func TestInlineProvider_InvalidPEMFormat(t *testing.T) {
	// Invalid PEM data with remaining content
	pemData := generateInvalidPEMData("CERTIFICATE") + "\ninvalid remaining data"

	_, err := keyprovider.CreateKeyProvider("inline", map[string]interface{}{
		"certs": pemData,
	})
	if err == nil {
		t.Fatalf("expected error for invalid PEM format with remaining data")
	}
}

func TestInlineProvider_InvalidKeyPEMFormat(t *testing.T) {
	// Invalid PEM data with remaining content for keys
	pemData := generateInvalidPEMData("PUBLIC KEY") + "\ninvalid remaining data"

	_, err := keyprovider.CreateKeyProvider("inline", map[string]interface{}{
		"keys": pemData,
	})
	if err == nil {
		t.Fatalf("expected error for invalid key PEM format with remaining data")
	}
}

func TestInlineProvider_InvalidPublicKeyData(t *testing.T) {
	// Valid PEM structure but invalid public key data
	pemData := generateInvalidPEMData("PUBLIC KEY")

	_, err := keyprovider.CreateKeyProvider("inline", map[string]interface{}{
		"keys": pemData,
	})
	if err == nil {
		t.Fatalf("expected error for invalid public key data")
	}
}

func TestInlineProvider_InvalidRSAPublicKeyData(t *testing.T) {
	// Valid PEM structure but invalid RSA public key data
	pemData := generateInvalidPEMData("RSA PUBLIC KEY")

	_, err := keyprovider.CreateKeyProvider("inline", map[string]interface{}{
		"keys": pemData,
	})
	if err == nil {
		t.Fatalf("expected error for invalid RSA public key data")
	}
}

func TestInlineProvider_MarshalOptionsError(t *testing.T) {
	// Pass a channel which cannot be marshaled to JSON
	_, err := keyprovider.CreateKeyProvider("inline", make(chan int))
	if err == nil {
		t.Fatalf("expected error when marshaling invalid options type")
	}
	if !strings.Contains(err.Error(), "failed to marshal options") {
		t.Fatalf("expected marshal error, got: %v", err)
	}
}

func TestInlineProvider_UnmarshalOptionsError(t *testing.T) {
	// This should cause an unmarshal error - using a struct that can't be unmarshaled into inlineOptions
	type invalidStruct struct {
		InvalidField func() `json:"invalid_field"`
	}
	invalid := invalidStruct{InvalidField: func() {}}

	_, err := keyprovider.CreateKeyProvider("inline", invalid)
	if err == nil {
		t.Fatalf("expected error when unmarshaling invalid options")
	}
}

func TestInlineProvider_RSAPublicKeyPKIXFallback(t *testing.T) {
	// Create a valid RSA private key and generate PKCS1 format public key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Marshal as PKCS1 format (which should trigger the fallback path)
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubKeyBytes})

	provider, err := keyprovider.CreateKeyProvider("inline", map[string]interface{}{
		"keys": string(pemBytes),
	})
	if err != nil {
		t.Fatalf("unexpected error constructing provider: %v", err)
	}

	keys, err := provider.GetKeys(context.Background())
	if err != nil {
		t.Fatalf("unexpected error retrieving keys: %v", err)
	}

	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	gotKey, ok := keys[0].Key.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected RSA public key, got %T", keys[0].Key)
	}

	if gotKey.N.Cmp(privKey.N) != 0 || gotKey.E != privKey.E {
		t.Fatalf("returned key does not match the provided one")
	}
}

func TestInlineProvider_NonRSAPublicKeyPKIXFail(t *testing.T) {
	// Create invalid public key data that will fail PKIX parsing for non-RSA type
	pemData := generateInvalidPEMData("PUBLIC KEY")

	_, err := keyprovider.CreateKeyProvider("inline", map[string]interface{}{
		"keys": pemData,
	})
	if err == nil {
		t.Fatalf("expected error for invalid non-RSA public key data")
	}
	if !strings.Contains(err.Error(), "failed to parse public key") {
		t.Fatalf("expected public key parse error, got: %v", err)
	}
}

func TestInlineProvider_WhitespaceOnlyInput(t *testing.T) {
	// Test with whitespace-only input which gets trimmed to empty and then parsed
	// This should trigger the "no certificates found" error case
	_, err := keyprovider.CreateKeyProvider("inline", map[string]interface{}{
		"certs": "   \n\t  \n   ",
	})
	if err == nil {
		t.Fatalf("expected error for whitespace-only certs input")
	}
	if !strings.Contains(err.Error(), "no certificates found") {
		t.Fatalf("expected 'no certificates found' error, got: %v", err)
	}

	_, err = keyprovider.CreateKeyProvider("inline", map[string]interface{}{
		"keys": "   \n\t  \n   ",
	})
	if err == nil {
		t.Fatalf("expected error for whitespace-only keys input")
	}
	if !strings.Contains(err.Error(), "no public keys found") {
		t.Fatalf("expected 'no public keys found' error, got: %v", err)
	}
}

func TestInlineProvider_PublicKeySuccessfulPKIXParsing(t *testing.T) {
	// Test the case where PKIX parsing succeeds for a PUBLIC KEY type (not RSA)
	// This ensures we cover the branch where we don't fall back to PKCS1 parsing
	ecPem, wantKey := generateECPublicKeyPEM(t)

	provider, err := keyprovider.CreateKeyProvider("inline", map[string]interface{}{
		"keys": ecPem,
	})
	if err != nil {
		t.Fatalf("unexpected error constructing provider: %v", err)
	}

	keys, err := provider.GetKeys(context.Background())
	if err != nil {
		t.Fatalf("unexpected error retrieving keys: %v", err)
	}

	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	gotKey, ok := keys[0].Key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected ECDSA public key, got %T", keys[0].Key)
	}

	if gotKey.X.Cmp(wantKey.X) != 0 || gotKey.Y.Cmp(wantKey.Y) != 0 {
		t.Fatalf("returned key does not match the provided one")
	}
}

func TestInlineProvider_EdgeCaseJSON(t *testing.T) {
	// Test some JSON edge cases to increase init function coverage
	tests := []struct {
		name    string
		options interface{}
		wantErr bool
	}{
		{
			name:    "nil options",
			options: nil,
			wantErr: false,
		},
		{
			name:    "empty map",
			options: map[string]interface{}{},
			wantErr: false,
		},
		{
			name: "extra fields ignored",
			options: map[string]interface{}{
				"certs":       "",
				"keys":        "",
				"extra_field": "ignored",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := keyprovider.CreateKeyProvider("inline", tt.options)
			if (err != nil) != tt.wantErr {
				t.Fatalf("expected error: %v, got: %v", tt.wantErr, err)
			}
		})
	}
}
