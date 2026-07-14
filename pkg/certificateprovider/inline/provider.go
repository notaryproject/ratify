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

package inline

import (
	"context"
	"crypto/x509"

	"github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/pkg/certificateprovider"
)

const (
	// ValueParameter is the name of the parameter that contains the certificate (chain) as a string in PEM format
	ValueParameter        = "value"
	providerName   string = "inline"
)

type inlineCertProvider struct{}

// init calls to register the provider
func init() {
	certificateprovider.Register(providerName, Create())
}

func Create() certificateprovider.CertificateProvider {
	// returning a simple provider for now, overtime we will add metrics and other related properties
	return &inlineCertProvider{}
}

// returns an array of certificates based on certificate properties defined in attrib map
func (s *inlineCertProvider) GetCertificates(_ context.Context, attrib map[string]string) ([]*x509.Certificate, certificateprovider.CertificatesStatus, error) {
	value, ok := attrib[ValueParameter]
	if !ok {
		return nil, nil, errors.ErrorCodeConfigInvalid.WithDetail("value parameter is not set").WithComponentType(errors.CertProvider)
	}

	certs, err := certificateprovider.DecodeCertificates([]byte(value))
	if err != nil {
		return nil, nil, errors.ErrorCodeCertInvalid.WithComponentType(errors.CertProvider)
	}
	return certs, nil, nil
}
