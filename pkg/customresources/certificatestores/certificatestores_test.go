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

package certificatestores

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/notaryproject/ratify/v2/internal/constants"
	ctxUtils "github.com/notaryproject/ratify/v2/internal/context"
	"github.com/notaryproject/ratify/v2/pkg/utils"
)

const (
	namespace1              = "namespace1"
	namespace2              = "namespace2"
	name1                   = "name1"
	name2                   = "name2"
	store1                  = namespace1 + "/" + name1
	store2                  = namespace2 + "/" + name2
	ratifyDeployedNamespace = "sample"
	storeInRatifyNS         = ratifyDeployedNamespace + "/" + name1
	storeWithoutNamespace   = name1
)

var (
	cert1          = generateTestCert()
	cert2          = generateTestCert()
	certInRatifyNS = generateTestCert()
)

func TestCertStoresOperations(t *testing.T) {
	activeCertStores := NewActiveCertStores()
	ctx := context.Background()
	certStore1 := []*x509.Certificate{cert1}

	activeCertStores.AddStoreError(store1, errors.New("error1"))
	if _, err := activeCertStores.GetCertsFromStore(ctx, store1); err == nil {
		t.Fatalf("expect to get error, but got nil")
	}

	activeCertStores.AddStore(store1, certStore1)
	certs, _ := activeCertStores.GetCertsFromStore(ctx, store1)
	if len(certs) != 1 {
		t.Fatalf("expect to get 1 certificate, but got: %d", len(certs))
	}

	activeCertStores.DeleteStore(store1)
	certs, _ = activeCertStores.GetCertsFromStore(ctx, store1)
	if len(certs) != 0 {
		t.Fatalf("expect to get 0 certificate, but got: %d", len(certs))
	}
}

func TestGetCertsFromStore(t *testing.T) {
	activeCertStores := NewActiveCertStores()
	activeCertStores.AddStore(store1, []*x509.Certificate{cert1})
	activeCertStores.AddStore(store2, []*x509.Certificate{cert2})
	activeCertStores.AddStore(storeInRatifyNS, []*x509.Certificate{certInRatifyNS})

	os.Setenv(utils.RatifyNamespaceEnvVar, ratifyDeployedNamespace)
	defer os.Unsetenv(utils.RatifyNamespaceEnvVar)

	testCases := []struct {
		name         string
		scope        string
		storeName    string
		expectedCert *x509.Certificate
	}{
		{
			name:         "clustered access to store with namespace",
			scope:        constants.EmptyNamespace,
			storeName:    store1,
			expectedCert: cert1,
		},
		{
			name:         "clustered access to store without namespace",
			scope:        constants.EmptyNamespace,
			storeName:    storeWithoutNamespace,
			expectedCert: certInRatifyNS,
		},
		{
			name:         "clustered access to nonexisting store",
			scope:        constants.EmptyNamespace,
			storeName:    "nonexisting",
			expectedCert: nil,
		},
		{
			name:         "namespaced access to store under same namespace",
			scope:        namespace1,
			storeName:    store1,
			expectedCert: cert1,
		},
		{
			name:         "namespaced access to nonexisting store",
			scope:        "nonexisting",
			storeName:    "nonexisting/nonexisting",
			expectedCert: nil,
		},
		{
			name:         "namespaced access to store under different namespace",
			scope:        namespace1,
			storeName:    store2,
			expectedCert: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := ctxUtils.SetContextWithNamespace(context.Background(), tc.scope)
			certs, _ := activeCertStores.GetCertsFromStore(ctx, tc.storeName)
			if len(certs) == 0 {
				if tc.expectedCert != nil {
					t.Fatalf("Expected to get certificate, but got none")
				}
			} else {
				if certs[0] != tc.expectedCert {
					t.Fatalf("Got unexpected certificate")
				}
			}
		})
	}
}

func generateTestCert() *x509.Certificate {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil
	}

	// Create a certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Example Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil
	}

	return cert
}
