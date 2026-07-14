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
package types

// This class is based on implementation from  azure secret store csi provider
// Source: https://github.com/Azure/secrets-store-csi-driver-provider-azure/tree/release-1.4/pkg/provider
const (
	// KeyVaultURIParameter is the name of the key vault URI parameter
	KeyVaultURIParameter = "vaultURI"
	// CloudNameParameter is the name of the cloud name parameter
	CloudNameParameter = "cloudName"
	// TenantIDParameter is the name of the tenant ID parameter
	TenantIDParameter = "tenantID"
	// ClientIDParameter is the name of the client ID parameter
	// This clientID is used for workload identity
	ClientIDParameter = "clientID"
	// CertificatesParameter is the name of the objects parameter
	CertificatesParameter = "certificates"
	// Static string for certificate type
	CertificateType = "CERTIFICATE"

	// key of the certificate status property
	CertificatesStatus = "Certificates"
	// Static string for certificate name for the certificate status property
	CertificateName = "CertificateName"
	// Certificate version string for the certificate status property
	CertificateVersion = "Version"
	// Last refreshed string for the certificate status property
	CertificateLastRefreshed = "LastRefreshed"
)

// KeyVaultCertificate holds keyvault certificate related config
type KeyVaultCertificate struct {
	// the name of the Azure Key Vault certificate
	CertificateName string `json:"certificateName" yaml:"certificateName"`
	// the version of the Azure Key Vault certificate
	CertificateVersion string `json:"certificateVersion" yaml:"certificateVersion"`
}

// Certificate holds content and metadata of a keyvault certificate file
type Certificate struct {
	Content         []byte
	CertificateName string
	Version         string
}

// StringArray holds a list of strings
type StringArray struct {
	Array []string `json:"array" yaml:"array"`
}
