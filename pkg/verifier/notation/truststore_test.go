// Copyright The Ratify Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package notation

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"reflect"
	"testing"

	"github.com/notaryproject/notation-go/verifier/truststore"
)

const (
	certStr     = "-----BEGIN CERTIFICATE-----\nMIIDsDCCApigAwIBAgIQMdNmNTKwQ9aOe6iuMRokDzANBgkqhkiG9w0BAQsFADBa\nMQswCQYDVQQGEwJVUzELMAkGA1UECBMCV0ExEDAOBgNVBAcTB1NlYXR0bGUxDzAN\nBgNVBAoTBk5vdGFyeTEbMBkGA1UEAxMSd2FiYml0LW5ldHdvcmtzLmlvMB4XDTIy\nMTIxNDIxNTAzMVoXDTIzMTIxNDIyMDAzMVowWjELMAkGA1UEBhMCVVMxCzAJBgNV\nBAgTAldBMRAwDgYDVQQHEwdTZWF0dGxlMQ8wDQYDVQQKEwZOb3RhcnkxGzAZBgNV\nBAMTEndhYmJpdC1uZXR3b3Jrcy5pbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\nAQoCggEBAOP6AHCFz41kRqsAiv6guFtQVsrzMgzoCX7o9NtQ57rr8BESP1LTGRAO\n4bjyP0i+at5uwIm4tdz0gW+g0P+f9bmfiScYgOFuxAJxLkMkBWPN3dJ9ulP/OGgB\n6mSCsEGreB3uaGc5rMbWCRaux65bMPjEzx5ex0qRSsn+fFMTwINPQUJpXSvi/W2/\n1umEWE1x59x0vlkP2dN7CXtB5/Bh01QNNbMdKU9saYn0kaBrCYZLwr6AxFRzLqLM\nQggy/6bOp/+cTTVqTiChMcdyIX52GRr2lChRsB34dDPYxDeKSI5LoRy07bveLjex\n4wm9+vx/WOSS5z0QPvE/v8avuIkMXR0CAwEAAaNyMHAwDgYDVR0PAQH/BAQDAgeA\nMAkGA1UdEwQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHwYDVR0jBBgwFoAUwVvE\nvqQPxnE6j6pfX6jpSyv2dOAwHQYDVR0OBBYEFMFbxL6kD8ZxOo+qX1+o6Usr9nTg\nMA0GCSqGSIb3DQEBCwUAA4IBAQDE61FLbagvlCcXf0zcv+mUQ+0HvDVs7ofQe3Yw\naz7gAwxgTspr+jIFQWnPOOBupsyx/jucoz78ndbc5DGWPs2Qz/pIEGnLto2W/PYy\nas/9n8xHxembS4n/Mxxp60PF6ladi/nJAtDJds67sBeqLOfJzh6jV2uQvW7PXe1P\nOMSUHbBn8AfArZ/9njusiLs75+XcAgpnBFqKVv2Vd/INp2YQpVzusuiodeM8A9Qt\n/5xykjdCJw3ceZxD7dSkHgchKZPINFBYHt/EkN/d8mXFOKjGXZyntp4PO6PJ2HYN\nhMMDwdNu4mBmlMTdZMPEpIZIeW7G0P9KpCuvvD7po7NxdBgI\n-----END CERTIFICATE-----\n"
	certStr2    = "-----BEGIN CERTIFICATE-----\nMIIDsDCCApigAwIBAgIQFJMQeqR8TRuHqNu+x0MuEDANBgkqhkiG9w0BAQsFADBa\nMQswCQYDVQQGEwJVUzELMAkGA1UECBMCV0ExEDAOBgNVBAcTB1NlYXR0bGUxDzAN\nBgNVBAoTBk5vdGFyeTEbMBkGA1UEAxMSd2FiYml0LW5ldHdvcmtzLmlvMB4XDTIz\nMDExMTE5MjAxMloXDTI0MDExMTE5MzAxMlowWjELMAkGA1UEBhMCVVMxCzAJBgNV\nBAgTAldBMRAwDgYDVQQHEwdTZWF0dGxlMQ8wDQYDVQQKEwZOb3RhcnkxGzAZBgNV\nBAMTEndhYmJpdC1uZXR3b3Jrcy5pbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\nAQoCggEBAMh7F6sZyeiQRva83SvQu0PbsyD4zkEeWAyj03n1dx91FEeEXItCr+Y1\nghQKgdBOY/wJQmSq/We1e+17NoNICrzy2Y1sOVMYR5sx8H/UxO3q8oS7bxctFy+e\nHs4BxlHIqeIiWnz9bFAJFqV6BkJDVjp9k5QfHlkqH08WBvm/D8YTpWzvEPn+71ZG\nN1RKqFUeeM949oGGnC63vVMRRYIx2LoJliNZXdj9qoOHZksDrX2jkgPykkOYcmfo\n9CH9v0JNX+0t0Enp0ruUFK1pSZW+TicI22GvENYHGZNZ0m+6oD5ePRZoYhWyAzgZ\nndHO5bYh3yC7DMc6ssOEJeNN0I2+iLUCAwEAAaNyMHAwDgYDVR0PAQH/BAQDAgeA\nMAkGA1UdEwQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHwYDVR0jBBgwFoAUYhhf\nPFgAqU8PF3ClvfKs67HmpWwwHQYDVR0OBBYEFGIYXzxYAKlPDxdwpb3yrOux5qVs\nMA0GCSqGSIb3DQEBCwUAA4IBAQCXu1w+6s2RO2/KPmC+29m9EjbDReI4bGlDGgiv\nwk1fmvPvDrqL4Ebpcrb1nstNlsxpKYQP+3Vi8gPiqNQ7JvPStd1NBu+ViCXdvOe5\nCtN7tBFTCBgdgXNZ9bvIM2dS+xW/ZAJdyHbV9Hn77+rs/uCDHtbaQMJ3N9LGW8GR\nGY+uYylrrCrjb9fzotMaONnF9c1GKiANskc9371wbaninpxcwMNA5j027XzfnMEW\nm807wjlNV3Kuf4fdDpzBLe940iplfTlQMylWMqgANpEw4EqHCrBJPQAHfQEpQlo+\n9H72lrqOiYNNwApfB9P+UqMDi1B7T2yzfvXcqQ75FpSRIxzK\n-----END CERTIFICATE-----\n"
	caCertStr   = "-----BEGIN CERTIFICATE-----\nMIIDNTCCAh2gAwIBAgIUbLzOMsPOGflj7TS34tzjs5vBWYIwDQYJKoZIhvcNAQEL\nBQAwKjEPMA0GA1UECgwGUmF0aWZ5MRcwFQYDVQQDDA5SYXRpZnkgUm9vdCBDQTAe\nFw0yMzAzMTAwMTEwMjlaFw0yNDAzMDkwMTEwMjlaMCoxDzANBgNVBAoMBlJhdGlm\neTEXMBUGA1UEAwwOUmF0aWZ5IFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB\nDwAwggEKAoIBAQCeNlh95GnkHLBVSCoYmlPztNKw5jwmlZYWLgwZMOK0qKedlsZs\naxbb5YzQlIV/z8D+/DnsZ3hTmokset0hE6JDQ1lw5wjk1I8DijkjwiE3oVH5Kyv/\nPSUtbSP7LmNDG/2vtWBkyTltXf3SfqAazLXVd0IQqGTXie+2SJa9Q6UAZFWKB1t7\n0Js6rDyQULcUMSzvF39QBPHFcd9iuSZLPw9CGG7hHNTlaOQryukr6U9tjY4hLK7e\n1OdgyP17nXELIlL81ngoWufi3rLgePqfkg8GgwnWyFrDS2eZSofFqW0X80gDvEQ+\n5WGj4XklyGGHpwyR4qNMnv5hp7QMtDd62iyPAgMBAAGjUzBRMB0GA1UdDgQWBBQQ\nGxu39HR2ynlSR40ZySohaxKGMDAfBgNVHSMEGDAWgBQQGxu39HR2ynlSR40ZySoh\naxKGMDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB22EixNuBZ\nyeGtrtSpkVPer+nxKU+6upwXmLfTe3ZEbv1NqC2auUvD+EN/86+mJfeXhkdVHHoV\nteuXNVU0oJ4ocRUXkgA/jPUEnjXwYK661/N67mqr5wLHcKIt48yKNdMvfXO6tXSE\nx/xLQlX7v2JehEQtTv7axnYGoHOvKL2H0+lq5VN0rDnB5hb7LyRX9kQq6mszLzG5\nbypfWX1aReWViWU2d6hvVegDYFpRpPXE3o5FGWvrad91RXdSJLsjJGdYJMlUe3xR\n+guQHepJ0iCoreAr+0XkctcV0qlyOiIuikWMdrQiXXTIDCGTRNmD9XCTu5+2tZe+\nW2O8QLkvH3Fv\n-----END CERTIFICATE-----\n"
	leafCertStr = "-----BEGIN CERTIFICATE-----\nMIIC7jCCAdagAwIBAgIURNiOON+GKbFS8yFxG6aMRoMg29cwDQYJKoZIhvcNAQEL\nBQAwKjEPMA0GA1UECgwGUmF0aWZ5MRcwFQYDVQQDDA5SYXRpZnkgUm9vdCBDQTAe\nFw0yMzAzMTAwMTEwMjlaFw0yNDAzMDkwMTEwMjlaMBkxFzAVBgNVBAMMDnJhdGlm\neS5kZWZhdWx0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwUwGuWJ5\nDwspcL+7K+0XlkQ0g+sbyvfY0j0NdUmzsTPQNxsdUsbgYeidLnp0ruHKuHLq6Y9t\nEHUPF+A4S6lIi5OPhEkVxd/A5kzSX23WocJGmlew+Z/usjQdtiQ4ylYyHoHfPNrf\nrocbY21XQ3x2IM3yIo1QqSHNdCsE0UxsFI3j9XC+saIqrkr+k1SsI2AhhGRjXTke\nPNpOaJ+CRwsGz7PbnsACLbiAdOUJUGRkOlIl/p7hU2IcZUYTTGcKOFXP8DtbUJ+K\nQcBQOsfZyg36jvkpzmw/yAK00Uuc0X+5CaKfDKDw4MXvJFpRvG+Vc0mb5RB1E8py\neA6eXtUrZ5J4hQIDAQABox0wGzAZBgNVHREEEjAQgg5yYXRpZnkuZGVmYXVsdDAN\nBgkqhkiG9w0BAQsFAAOCAQEAHbiuodTJCDpCUu8tNjbww5ebTRznKZGnFmKQs5zU\no8KyCfLhR9/9zetDADwtWCQUvykFuHjx8tj41hALXXXafzkYPeTsfDmEoVWIJMQ1\nHqjbzc6bbxQAY7cC5HqM67fXYjPs1v3Uv3GZhF2EjBMqymKC+lZ/RSfktzN0iADn\nlwG9DrDibD739jBF09b3LHtdV55blN2wyB54DwMl5x0a4+bFYVj7fZzjctG4pH7T\njnBS69oxetPaqcRY7SQljJKaesiqx3CtiwVUpGTBexDtw6OIj9cWiCFT0lS3TfCh\nunfSQvVgezqE7txrFbXDQCgbl1jGagfia2ol7+IbLUR6TQ==\n-----END CERTIFICATE-----\n"
)

func TestGetCertificates_EmptyCertMap(t *testing.T) {
	certStore := verificationCertStores{
		trustStoreTypeCA: map[string]interface{}{
			"certstore1": []interface{}{"akv1", "akv2"},
			"certstore2": []interface{}{"akv3", "akv4"},
		},
	}
	store, err := newTrustStore([]string{}, certStore)
	if err != nil {
		panic("failed to parse verificationCertStores: " + err.Error())
	}
	if _, err := store.getCertificatesInternal(context.Background(), truststore.TypeCA, "certstore1"); err == nil {
		t.Fatalf("error expected if cert map is empty")
	}
}

func TestGetCertificates_certPath(t *testing.T) {
	// create a temporary certificate file
	tmpFile, err := os.CreateTemp("", "*.pem")
	if err != nil {
		t.Fatalf("failed to create temporary file: %v", err)
	}
	if _, err := tmpFile.Write([]byte(certStr)); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}

	trustStore := &trustStore{
		certPaths:  []string{tmpFile.Name()},
		certStores: certStoresByType{},
	}
	certs, err := trustStore.getCertificatesInternal(context.Background(), truststore.TypeCA, "")
	if err != nil {
		t.Fatalf("failed to get certs: %v", err)
	}

	if len(certs) != 1 || !certs[0].Equal(getCert(certStr)) {
		t.Fatalf("unexpected certificate returned")
	}

	// remove the temporary certificate file
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("failed to close temporary file: %v", err)
	}
}

func TestFilterValidCerts(t *testing.T) {
	trustStore := trustStore{}
	tests := []struct {
		name      string
		certs     []*x509.Certificate
		expect    []*x509.Certificate
		expectErr bool
	}{
		{
			name:      "CA cert",
			certs:     []*x509.Certificate{getCert(caCertStr)},
			expect:    []*x509.Certificate{getCert(caCertStr)},
			expectErr: false,
		},
		{
			name:      "self-signed cert",
			certs:     []*x509.Certificate{getCert(certStr)},
			expect:    []*x509.Certificate{getCert(certStr)},
			expectErr: false,
		},
		{
			name:      "invalid cert",
			certs:     []*x509.Certificate{getCert(leafCertStr)},
			expect:    nil,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := trustStore.filterValidCerts(tt.certs)
			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
			if !reflect.DeepEqual(result, tt.expect) {
				t.Errorf("expect %+v, got %+v", tt.expect, result)
			}
		})
	}
}

// convert string to a x509 certificate
func getCert(certString string) *x509.Certificate {
	block, _ := pem.Decode([]byte(certString))
	if block == nil {
		panic("failed to parse certificate PEM")
	}

	test, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	return test
}
