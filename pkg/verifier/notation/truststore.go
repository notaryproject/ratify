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
	"github.com/notaryproject/ratify/v2/pkg/controllers"
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
			var certStoreErr error
			// notation verifier does not consider specific named/versioned certificates within a key management provider resource
			if len(result) == 0 {
				logger.GetLogger(ctx, logOpt).Infof("no certificate fetched for Key Management Provider %+v", certStore)
				// check certificate store if key management provider does not have certificates.
				// NOTE: certificate store and key management provider should not be configured together.
				// User will be warned by the controller/CLI
				if result, certStoreErr = controllers.NamespacedCertStores.GetCertsFromStore(ctx, certStore); certStoreErr != nil {
					logger.GetLogger(ctx, logOpt).Warnf("unable to fetch certificates for Certificate Store %+v: %v", certStore, certStoreErr)
				}
				if len(result) == 0 {
					logger.GetLogger(ctx, logOpt).Warnf("no certificate fetched for Certificate Store %+v", certStore)
				} else {
					logger.GetLogger(ctx, logOpt).Info("Certificate Store has been deprecated since v1.2.0, please migrate to Key Management Provider following: https://ratify.dev/docs/reference/custom%20resources/key-management-providers#migrating-from-certificatestore-to-kmp")
				}
			}
			if err := parseErrFromKmpAndCertStore(kmpErr, certStoreErr); err != nil {
				return []*x509.Certificate{}, re.ErrorCodeCertInvalid.WithError(err).WithDetail(fmt.Sprintf("unable to fetch certificates from Key Management Provider and Certificate Store: %s", certStore))
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

// parseErrFromKmpAndCertStore prioritizes and returns the appropriate error from either KMP or CertStore.
// If the certStoreErr is a reconcile error while kmpErr is not, it returns certStoreErr,
// otherwise it returns kmpErr.
// A reconcile error occurs during CR reconciliation, indicating that the resource
// was applied by users.
// Since key management provider and certificate store are mutually exclusive,
// a reconcile error will only originate from one of them.
// Consequently, the reconcile error from one resource takes precedence over
// errors from the other.
// Note: this method should be deleted once certificate store is completely removed.
func parseErrFromKmpAndCertStore(kmpErr, certStoreErr error) error {
	if kmpErr == nil || certStoreErr == nil {
		return nil
	}
	if isReconcileError(certStoreErr) && !isReconcileError(kmpErr) {
		return certStoreErr
	}
	return kmpErr
}

// isReconcileError checks if the error is a reconcile error.
// If the error is not NotFound or Forbidden, it is considered as an error from KMP/CertStore reconciliation.
func isReconcileError(err error) bool {
	ratifyErr := &re.Error{}
	if errors.As(err, ratifyErr) {
		return ratifyErr.ErrorCode() != re.ErrorCodeNotFound && ratifyErr.ErrorCode() != re.ErrorCodeForbidden
	}
	return true
}
