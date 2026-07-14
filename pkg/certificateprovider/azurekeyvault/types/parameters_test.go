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
	"reflect"
	"testing"
)

func TestGetKeyVaultUri(t *testing.T) {
	tests := []struct {
		name       string
		parameters map[string]string
		expected   string
	}{
		{
			name: "empty",
			parameters: map[string]string{
				KeyVaultURIParameter: "",
			},
			expected: "",
		},
		{
			name: "not empty",
			parameters: map[string]string{
				KeyVaultURIParameter: "https://test.vault.azure.net/",
			},
			expected: "https://test.vault.azure.net/",
		},
		{
			name: "trim spaces",
			parameters: map[string]string{
				KeyVaultURIParameter: " https://test.vault.azure.net/ ",
			},
			expected: "https://test.vault.azure.net/",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := GetKeyVaultURI(test.parameters)
			if actual != test.expected {
				t.Errorf("GetKeyVaultUri() = %v, expected %v", actual, test.expected)
			}
		})
	}
}

func TestGetCloudName(t *testing.T) {
	tests := []struct {
		name       string
		parameters map[string]string
		expected   string
	}{
		{
			name: "empty",
			parameters: map[string]string{
				CloudNameParameter: "",
			},
			expected: "",
		},
		{
			name: "not empty",
			parameters: map[string]string{
				CloudNameParameter: "test",
			},
			expected: "test",
		},
		{
			name: "trim spaces",
			parameters: map[string]string{
				CloudNameParameter: " test ",
			},
			expected: "test",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := GetCloudName(test.parameters)
			if actual != test.expected {
				t.Errorf("GetCloudName() = %v, expected %v", actual, test.expected)
			}
		})
	}
}

func TestGetTenantID(t *testing.T) {
	tests := []struct {
		name       string
		parameters map[string]string
		expected   string
	}{
		{
			name: "empty",
			parameters: map[string]string{
				TenantIDParameter: "",
			},
			expected: "",
		},
		{
			name: "not empty",
			parameters: map[string]string{
				TenantIDParameter: "test",
			},
			expected: "test",
		},
		{
			name: "trim spaces",
			parameters: map[string]string{
				TenantIDParameter: " test ",
			},
			expected: "test",
		},
		{
			name: "new tenantID parameter",
			parameters: map[string]string{
				"tenantID": "test",
			},
			expected: "test",
		},
		{
			name: "new tenantID parameter with spaces",
			parameters: map[string]string{
				"tenantID": " test ",
			},
			expected: "test",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := GetTenantID(test.parameters)
			if actual != test.expected {
				t.Errorf("GetTenantID() = %v, expected %v", actual, test.expected)
			}
		})
	}
}

func TestGetClientID(t *testing.T) {
	tests := []struct {
		name       string
		parameters map[string]string
		expected   string
	}{
		{
			name: "empty",
			parameters: map[string]string{
				"clientID": "",
			},
			expected: "",
		},
		{
			name: "not empty",
			parameters: map[string]string{
				"clientID": "test",
			},
			expected: "test",
		},
		{
			name: "trim spaces",
			parameters: map[string]string{
				"clientID": " test ",
			},
			expected: "test",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := GetClientID(test.parameters)
			if actual != test.expected {
				t.Errorf("GetClientID() = %v, expected %v", actual, test.expected)
			}
		})
	}
}

func TestGetObjects(t *testing.T) {
	tests := []struct {
		name       string
		parameters map[string]string
		expected   string
	}{
		{
			name: "empty",
			parameters: map[string]string{
				CertificatesParameter: "",
			},
			expected: "",
		},
		{
			name: "not empty",
			parameters: map[string]string{
				CertificatesParameter: "test",
			},
			expected: "test",
		},
		{
			name: "trim spaces",
			parameters: map[string]string{
				CertificatesParameter: " test ",
			},
			expected: "test",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := GetCertificates(test.parameters)
			if actual != test.expected {
				t.Errorf("GetObjects() = %v, expected %v", actual, test.expected)
			}
		})
	}
}

func TestGetObjectsArray(t *testing.T) {
	tests := []struct {
		name     string
		objects  string
		expected StringArray
	}{
		{
			name:     "empty",
			objects:  "",
			expected: StringArray{},
		},
		{
			name:    "valid yaml",
			objects: "array:\n- |\n certificateName: secret1\n certificateVersion: \"\"\n- |\n certificateName: secret2\n certificateVersion: \"\"\n",
			expected: StringArray{
				Array: []string{
					"certificateName: secret1\ncertificateVersion: \"\"\n",
					"certificateName: secret2\ncertificateVersion: \"\"\n",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := GetCertificatesArray(test.objects)
			if err != nil {
				t.Errorf("GetCertificatesArray() error = %v", err)
			}
			if !reflect.DeepEqual(actual, test.expected) {
				t.Errorf("GetCertificatesArray() = %v, expected %v", actual, test.expected)
			}
		})
	}
}

func TestGetCertificatesArrayError(t *testing.T) {
	objects := "invalid"
	if _, err := GetCertificatesArray(objects); err == nil {
		t.Errorf("GetCertificatesArray() error is nil, expected error")
	}
}
