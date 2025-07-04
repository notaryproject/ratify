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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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

func TestInlineProvider_Success(t *testing.T) {
	pemStr, wantCert := generateSelfSignedPEM(t)

	// The inline provider is registered in init(). Retrieve it through the
	// keyprovider registry.
	provider, err := keyprovider.CreateKeyProvider("inline", pemStr)
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
}

func TestInlineProvider_OneValidAndOneInvalidCertificate(t *testing.T) {
	pemStr, _ := generateSelfSignedPEM(t)
	pemStr += "\n" + invalidCert // Append an invalid certificate

	_, err := keyprovider.CreateKeyProvider("inline", pemStr)
	if err == nil {
		t.Fatalf("expected error constructing provider with invalid certificate")
	}
}

func TestInlineProvider_ParseInvalidCertificate(t *testing.T) {
	_, err := keyprovider.CreateKeyProvider("inline", invalidCert)
	if err == nil {
		t.Fatalf("expected error when constructing provider with invalid certificate")
	}
}

func TestInlineProvider_ParseEmptyCertificates(t *testing.T) {
	_, err := keyprovider.CreateKeyProvider("inline", "")
	if err == nil {
		t.Fatalf("expected error when constructing provider with empty certificates")
	}
}

func TestInlineProvider_NoCertificates(t *testing.T) {
	_, err := keyprovider.CreateKeyProvider("inline", make(chan int))
	if err == nil {
		t.Fatalf("expected error when no certificates are supplied")
	}
}

func TestInlineProvider_BadCertificate(t *testing.T) {
	_, err := keyprovider.CreateKeyProvider("inline", []string{"not a valid pem certificate"})
	if err == nil {
		t.Fatalf("expected error for invalid certificate data")
	}
}
