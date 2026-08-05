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

// This class is based on implementation from azure secret store csi provider
// Source: https://github.com/Azure/secrets-store-csi-driver-provider-azure/tree/release-1.4/pkg/provider
import (
	"strings"

	"gopkg.in/yaml.v3"
)

// GetKeyVaultURI returns the key vault name
func GetKeyVaultURI(parameters map[string]string) string {
	return strings.TrimSpace(parameters[KeyVaultURIParameter])
}

// GetCloudName returns the cloud name
func GetCloudName(parameters map[string]string) string {
	return strings.TrimSpace(parameters[CloudNameParameter])
}

// GetTenantID returns the tenant ID
func GetTenantID(parameters map[string]string) string {
	// ref: https://github.com/Azure/secrets-store-csi-driver-provider-azure/issues/857
	tenantID := strings.TrimSpace(parameters["tenantID"])
	if tenantID != "" {
		return tenantID
	}

	return strings.TrimSpace(parameters[TenantIDParameter])
}

// GetClientID returns the client ID
func GetClientID(parameters map[string]string) string {
	return strings.TrimSpace(parameters[ClientIDParameter])
}

// GetCertificates returns the key vault objects
func GetCertificates(parameters map[string]string) string {
	return strings.TrimSpace(parameters[CertificatesParameter])
}

// GetCertificatesArray returns the key vault objects array
func GetCertificatesArray(objects string) (StringArray, error) {
	var a StringArray
	err := yaml.Unmarshal([]byte(objects), &a)

	return a, err
}
