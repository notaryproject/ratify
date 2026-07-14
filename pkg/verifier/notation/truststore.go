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
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/notaryproject/notation-go/verifier/truststore"
	re "github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/internal/logger"
	"github.com/notaryproject/ratify/v2/pkg/keymanagementprovider"
	"github.com/notaryproject/ratify/v2/pkg/utils"
)

var logOpt = logger.Option{
	ComponentType: logger.Verifier,
}

type trustStore struct {
	certPaths  []string
	certStores certStores
}

func newTrustStore(certPaths []string, verificationCertStores verificationCertStores) (*trustStore, error) {
	certStores, err := newCertStoreByType(verificationCertStores)
	if err != nil {
		return nil, re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Failed to create the trust store from the verificationCertStores parameter in Notation Verifier configuration: %+v", verificationCertStores)).WithError(err).WithRemediation("Please check the value of the verificationCertStores parameter according to the Notation Verifier configuration guide: https://ratify.dev/docs/plugins/verifier/notation#configuration")
	}
	store := &trustStore{
		certPaths:  certPaths,
		certStores: certStores,
	}
	return store, nil
}

// trustStore implements GetCertificates API of X509TrustStore interface: [https://pkg.go.dev/github.com/notaryproject/notation-go@v1.0.0-rc.3/verifier/truststore#X509TrustStore]
// Note: this api gets invoked when Ratify calls verify API, so the certificates
// will be loaded for each signature verification.
// And this API must follow the Notation Trust Store spec: https://github.com/notaryproject/notaryproject/blob/main/specs/trust-store-trust-policy.md#trust-store
func (s *trustStore) GetCertificates(ctx context.Context, trustStoreType truststore.Type, namedStore string) ([]*x509.Certificate, error) {
	certs, err := s.getCertificatesInternal(ctx, trustStoreType, namedStore)
	if err != nil {
		return nil, err
	}
	return s.filterValidCerts(certs)
}

func (s *trustStore) getCertificatesInternal(ctx context.Context, storeType truststore.Type, namedStore string) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0)

	certGroup := s.certStores.GetCertGroup(ctx, storeType, namedStore)
	// certs configured for this namedStore overrides cert path
	if len(certGroup) > 0 {
		for _, certStore := range certGroup {
			logger.GetLogger(ctx, logOpt).Debugf("truststore getting certStore %v", certStore)
			certMap, kmpErr := keymanagementprovider.GetCertificatesFromMap(ctx, certStore)
			if kmpErr != nil {
				logger.GetLogger(ctx, logOpt).Infof("unable to fetch certificates for Key Management Provider %+v: %v", certStore, kmpErr)
			}
			result := keymanagementprovider.FlattenKMPMap(certMap)
			if len(result) == 0 {
				logger.GetLogger(ctx, logOpt).Infof("no certificate fetched for Key Management Provider %+v", certStore)
			}
			if kmpErr != nil {
				return []*x509.Certificate{}, re.ErrorCodeCertInvalid.WithError(kmpErr).WithDetail(fmt.Sprintf("unable to fetch certificates from Key Management Provider: %s", certStore))
			}
			certs = append(certs, result...)
		}
		if len(certs) == 0 {
			return certs, fmt.Errorf("no certificates fetched in namedStore: %+v", namedStore)
		}
	} else {
		for _, path := range s.certPaths {
			bundledCerts, err := utils.GetCertificatesFromPath(path)
			if err != nil {
				return nil, err
			}
			certs = append(certs, bundledCerts...)
		}
	}
	logger.GetLogger(ctx, logOpt).Debugf("Trust store getCertificatesInternal , %v certs retrieved", len(certs))
	return certs, nil
}

// filterValidCerts keeps CA certificates and self-signed certs.
func (s *trustStore) filterValidCerts(certs []*x509.Certificate) ([]*x509.Certificate, error) {
	filteredCerts := make([]*x509.Certificate, 0)
	for _, cert := range certs {
		if !cert.IsCA {
			// check if it's a self-signed certificate.
			if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
				continue
			}
		}
		filteredCerts = append(filteredCerts, cert)
	}
	if len(filteredCerts) == 0 {
		return nil, errors.New("valid certificates must be provided, only CA certificates or self-signed signing certificates are supported")
	}
	return filteredCerts, nil
}
