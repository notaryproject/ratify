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

package azurekeyvault

// This class is based on implementation from  azure secret store csi provider
// Source: https://github.com/Azure/secrets-store-csi-driver-provider-azure/tree/release-1.4/pkg/provider
import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"reflect"
	"strings"
	"time"

	re "github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/internal/logger"
	"github.com/notaryproject/ratify/v2/pkg/certificateprovider"
	"github.com/notaryproject/ratify/v2/pkg/certificateprovider/azurekeyvault/types"
	"github.com/notaryproject/ratify/v2/pkg/metrics"
	"golang.org/x/crypto/pkcs12"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"gopkg.in/yaml.v2"
)

const (
	providerName      string = "azurekeyvault"
	PKCS12ContentType string = "application/x-pkcs12"
	PEMContentType    string = "application/x-pem-file"
)

var logOpt = logger.Option{
	ComponentType: logger.CertProvider,
}

type akvCertProvider struct{}

// init calls to register the provider
func init() {
	certificateprovider.Register(providerName, Create())
}

func Create() certificateprovider.CertificateProvider {
	// returning a simple provider for now, overtime we will add metrics and other related properties
	return &akvCertProvider{}
}

// returns an array of certificates based on certificate properties defined in attrib map
// get certificate retrieve the entire cert chain using getSecret API call
func (s *akvCertProvider) GetCertificates(ctx context.Context, attrib map[string]string) ([]*x509.Certificate, certificateprovider.CertificatesStatus, error) {
	keyvaultURI := types.GetKeyVaultURI(attrib)
	tenantID := types.GetTenantID(attrib)
	workloadIdentityClientID := types.GetClientID(attrib)

	if keyvaultURI == "" {
		return nil, nil, re.ErrorCodeConfigInvalid.NewError(re.CertProvider, providerName, re.AKVLink, nil, "keyvaultUri is not set", re.HideStackTrace)
	}
	if tenantID == "" {
		return nil, nil, re.ErrorCodeConfigInvalid.NewError(re.CertProvider, providerName, re.AKVLink, nil, "tenantID is not set", re.HideStackTrace)
	}
	if workloadIdentityClientID == "" {
		return nil, nil, re.ErrorCodeConfigInvalid.NewError(re.CertProvider, providerName, re.AKVLink, nil, "clientID is not set", re.HideStackTrace)
	}

	keyVaultCerts, err := getKeyvaultRequestObj(ctx, attrib)
	if err != nil {
		return nil, nil, re.ErrorCodeConfigInvalid.NewError(re.CertProvider, providerName, re.AKVLink, err, "failed to get keyvault request object from provider attributes", re.HideStackTrace)
	}

	if len(keyVaultCerts) == 0 {
		return nil, nil, re.ErrorCodeConfigInvalid.NewError(re.CertProvider, providerName, re.EmptyLink, nil, "no keyvault certificate configured", re.HideStackTrace)
	}

	// credProvider is nil, so we will create a new workload identity credential inside the function
	// For testing purposes, we can pass in a mock credential provider
	var credProvider azcore.TokenCredential
	secretKVClient, err := initializeKvClient(keyvaultURI, tenantID, workloadIdentityClientID, credProvider)
	if err != nil {
		return nil, nil, re.ErrorCodePluginInitFailure.NewError(re.CertProvider, providerName, re.AKVLink, err, "failed to get keyvault client", re.HideStackTrace)
	}

	certs := []*x509.Certificate{}
	certsStatus := []map[string]string{}
	for _, keyVaultCert := range keyVaultCerts {
		logger.GetLogger(ctx, logOpt).Debugf("fetching secret from key vault, certName %v,  keyvault %v", keyVaultCert.CertificateName, keyvaultURI)

		// fetch the object from Key Vault
		// GetSecret is required so we can fetch the entire cert chain. See issue https://github.com/notaryproject/ratify/v2/issues/695 for details
		startTime := time.Now()

		secretResponse, err := secretKVClient.GetSecret(ctx, keyVaultCert.CertificateName, keyVaultCert.CertificateVersion, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get secret objectName:%s, objectVersion:%s, error: %w", keyVaultCert.CertificateName, keyVaultCert.CertificateVersion, err)
		}
		secretBundle := secretResponse.SecretBundle

		certResult, certProperty, err := getCertsFromSecretBundle(ctx, secretBundle, keyVaultCert.CertificateName)

		if err != nil {
			return nil, nil, fmt.Errorf("failed to get certificates from secret bundle:%w", err)
		}

		metrics.ReportAKVCertificateDuration(ctx, time.Since(startTime).Milliseconds(), keyVaultCert.CertificateName)
		certs = append(certs, certResult...)
		certsStatus = append(certsStatus, certProperty...)
	}

	return certs, getCertStatusMap(certsStatus), nil
}

// azure keyvault provider certificate status is a map from "certificates" key to an array of of certificate status
func getCertStatusMap(certsStatus []map[string]string) certificateprovider.CertificatesStatus {
	status := certificateprovider.CertificatesStatus{}
	status[types.CertificatesStatus] = certsStatus
	return status
}

// parse the requested keyvault cert object from the input attributes
func getKeyvaultRequestObj(ctx context.Context, attrib map[string]string) ([]types.KeyVaultCertificate, error) {
	keyVaultCerts := []types.KeyVaultCertificate{}

	certificatesStrings := types.GetCertificates(attrib)
	if certificatesStrings == "" {
		return nil, re.ErrorCodeConfigInvalid.NewError(re.CertProvider, providerName, re.EmptyLink, nil, "certificates is not set", re.HideStackTrace)
	}

	logger.GetLogger(ctx, logOpt).Debugf("certificates string defined in ratify certStore class, certificates %v", certificatesStrings)

	objects, err := types.GetCertificatesArray(certificatesStrings)
	if err != nil {
		return nil, re.ErrorCodeDataDecodingFailure.NewError(re.CertProvider, providerName, re.EmptyLink, err, "failed to yaml unmarshal objects", re.HideStackTrace)
	}
	logger.GetLogger(ctx, logOpt).Debugf("unmarshaled objects yaml, objectsArray %v", objects.Array)

	for i, object := range objects.Array {
		var keyVaultCert types.KeyVaultCertificate
		if err = yaml.Unmarshal([]byte(object), &keyVaultCert); err != nil {
			return nil, re.ErrorCodeDataDecodingFailure.NewError(re.CertProvider, providerName, re.EmptyLink, err, fmt.Sprintf("unmarshal failed for keyVaultCerts at index: %d", i), re.HideStackTrace)
		}
		// remove whitespace from all fields in keyVaultCert
		formatKeyVaultCertificate(&keyVaultCert)

		keyVaultCerts = append(keyVaultCerts, keyVaultCert)
	}

	logger.GetLogger(ctx, logOpt).Debugf("unmarshaled %v key vault objects, keyVaultObjects: %v", len(keyVaultCerts), keyVaultCerts)
	return keyVaultCerts, nil
}

// return a certificate status object that consist of the cert name, version and last refreshed time
func getCertStatusProperty(certificateName, version, lastRefreshed string) map[string]string {
	certProperty := map[string]string{}
	certProperty[types.CertificateName] = certificateName
	certProperty[types.CertificateVersion] = version
	certProperty[types.CertificateLastRefreshed] = lastRefreshed
	return certProperty
}

// formatKeyVaultCertificate formats the fields in KeyVaultCertificate
func formatKeyVaultCertificate(object *types.KeyVaultCertificate) {
	if object == nil {
		return
	}
	objectPtr := reflect.ValueOf(object)
	objectValue := objectPtr.Elem()

	for i := 0; i < objectValue.NumField(); i++ {
		field := objectValue.Field(i)
		if field.Type() != reflect.TypeOf("") {
			continue
		}
		str := field.Interface().(string)
		str = strings.TrimSpace(str)
		field.SetString(str)
	}
}

func initializeKvClient(keyVaultEndpoint, tenantID, clientID string, credProvider azcore.TokenCredential) (*azsecrets.Client, error) {
	// Trim any trailing slash from the endpoint
	kvEndpoint := strings.TrimSuffix(keyVaultEndpoint, "/")

	// If credProvider is nil, create the default credential
	if credProvider == nil {
		var err error
		credProvider, err = azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{
			ClientID: clientID,
			TenantID: tenantID,
		})
		if err != nil {
			return nil, re.ErrorCodeAuthDenied.WithDetail("failed to create workload identity credential").WithError(err)
		}
	}

	// create azsecrets client
	secretKVClient, err := azsecrets.NewClient(kvEndpoint, credProvider, nil)
	if err != nil {
		return nil, re.ErrorCodeConfigInvalid.WithDetail("Failed to create Key Vault client").WithError(err)
	}

	return secretKVClient, nil
}

// Parse the secret bundle and return an array of certificates
// In a certificate chain scenario, all certificates from root to leaf will be returned
func getCertsFromSecretBundle(ctx context.Context, secretBundle azsecrets.SecretBundle, certName string) ([]*x509.Certificate, []map[string]string, error) {
	if secretBundle.ContentType == nil || secretBundle.Value == nil || secretBundle.ID == nil {
		return nil, nil, re.ErrorCodeCertInvalid.NewError(re.CertProvider, providerName, re.EmptyLink, nil, "found invalid secret bundle for certificate  %s, contentType, value, and id must not be nil", re.HideStackTrace)
	}

	version := getObjectVersion(string(*secretBundle.ID))

	// This aligns with notation akv implementation
	// akv plugin supports both PKCS12 and PEM. https://github.com/Azure/notation-azure-kv/blob/558e7345ef8318783530de6a7a0a8420b9214ba8/Notation.Plugin.AzureKeyVault/KeyVault/KeyVaultClient.cs#L192
	if *secretBundle.ContentType != PKCS12ContentType &&
		*secretBundle.ContentType != PEMContentType {
		return nil, nil, re.ErrorCodeCertInvalid.NewError(re.CertProvider, providerName, re.EmptyLink, nil, fmt.Sprintf("certificate %s version %s, unsupported secret content type %s, supported type are %s and %s", certName, version, *secretBundle.ContentType, PKCS12ContentType, PEMContentType), re.HideStackTrace)
	}

	results := []*x509.Certificate{}
	certsStatus := []map[string]string{}
	lastRefreshed := time.Now().Format(time.RFC3339)

	data := []byte(*secretBundle.Value)

	if *secretBundle.ContentType == PKCS12ContentType {
		p12, err := base64.StdEncoding.DecodeString(*secretBundle.Value)
		if err != nil {
			return nil, nil, re.ErrorCodeCertInvalid.NewError(re.CertProvider, providerName, re.EmptyLink, err, fmt.Sprintf("azure keyvault certificate provider: failed to decode PKCS12 Value. Certificate %s, version %s", certName, version), re.HideStackTrace)
		}

		blocks, err := pkcs12.ToPEM(p12, "")
		if err != nil {
			return nil, nil, re.ErrorCodeCertInvalid.NewError(re.CertProvider, providerName, re.EmptyLink, err, fmt.Sprintf("azure keyvault certificate provider: failed to convert PKCS12 Value to PEM. Certificate %s, version %s", certName, version), re.HideStackTrace)
		}

		var pemData []byte
		for _, b := range blocks {
			pemData = append(pemData, pem.EncodeToMemory(b)...)
		}
		data = pemData
	}

	block, rest := pem.Decode(data)

	for block != nil {
		switch block.Type {
		case "PRIVATE KEY":
			logger.GetLogger(ctx, logOpt).Warnf("azure keyvault certificate provider: certificate %s, version %s private key skipped. Please see doc to learn how to create a new certificate in keyvault with non exportable keys. https://learn.microsoft.com/en-us/azure/key-vault/certificates/how-to-export-certificate?tabs=azure-cli#exportable-and-non-exportable-keys", certName, version)
		case "CERTIFICATE":
			var pemData []byte
			pemData = append(pemData, pem.EncodeToMemory(block)...)
			decodedCerts, err := certificateprovider.DecodeCertificates(pemData)
			if err != nil {
				return nil, nil, re.ErrorCodeCertInvalid.NewError(re.CertProvider, providerName, re.EmptyLink, err, fmt.Sprintf("azure keyvault certificate provider: failed to decode Certificate %s, version %s", certName, version), re.HideStackTrace)
			}
			for _, cert := range decodedCerts {
				results = append(results, cert)
				certProperty := getCertStatusProperty(certName, version, lastRefreshed)
				certsStatus = append(certsStatus, certProperty)
			}
		default:
			logger.GetLogger(ctx, logOpt).Warnf("certificate '%s', version '%s': azure keyvault certificate provider detected unknown block type %s", certName, version, block.Type)
		}

		block, rest = pem.Decode(rest)
		if block == nil && len(rest) > 0 {
			return nil, nil, re.ErrorCodeCertInvalid.NewError(re.CertProvider, providerName, re.EmptyLink, nil, fmt.Sprintf("certificate '%s', version '%s': azure keyvault certificate provider error, block is nil and remaining block to parse > 0", certName, version), re.HideStackTrace)
		}
	}
	logger.GetLogger(ctx, logOpt).Debugf("azurekeyvault certprovider getCertsFromSecretBundle: %v certificates parsed, Certificate '%s', version '%s'", len(results), certName, version)
	return results, certsStatus, nil
}

// getObjectVersion parses the id to retrieve the version
// of object fetched
// example id format - https://kindkv.vault.azure.net/secrets/actual/1f304204f3624873aab40231241243eb
// TODO (aramase) follow up on https://github.com/Azure/azure-rest-api-specs/issues/10825 to provide
// a native way to obtain the version
func getObjectVersion(id string) string {
	splitID := strings.Split(id, "/")
	return splitID[len(splitID)-1]
}
