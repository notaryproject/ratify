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
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/ratify-project/ratify/pkg/certificateprovider/azurekeyvault/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestFormatKeyVaultCertificate(t *testing.T) {
	cases := []struct {
		desc                   string
		keyVaultObject         types.KeyVaultCertificate
		expectedKeyVaultObject types.KeyVaultCertificate
	}{
		{
			desc: "leading and trailing whitespace trimmed from all fields",
			keyVaultObject: types.KeyVaultCertificate{
				CertificateName:    "cert1     ",
				CertificateVersion: "",
			},
			expectedKeyVaultObject: types.KeyVaultCertificate{
				CertificateName:    "cert1",
				CertificateVersion: "",
			},
		},
		{
			desc: "no data loss for already sanitized object",
			keyVaultObject: types.KeyVaultCertificate{
				CertificateName:    "cert1",
				CertificateVersion: "version1",
			},
			expectedKeyVaultObject: types.KeyVaultCertificate{
				CertificateName:    "cert1",
				CertificateVersion: "version1",
			},
		},
	}

	for i, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			formatKeyVaultCertificate(&cases[i].keyVaultObject)
			if !reflect.DeepEqual(cases[i].keyVaultObject, cases[i].expectedKeyVaultObject) {
				t.Fatalf("expected: %+v, but got: %+v", tc.expectedKeyVaultObject, tc.keyVaultObject)
			}
		})
	}
}

// Mock clients
type MockAzSecretsClient struct {
	mock.Mock
}

type MockWorkloadIdentityCredential struct {
	mock.Mock
}

// Mock functions
func (m *MockWorkloadIdentityCredential) NewWorkloadIdentityCredential(options *azidentity.WorkloadIdentityCredentialOptions) (*MockWorkloadIdentityCredential, error) {
	args := m.Called(options)
	return args.Get(0).(*MockWorkloadIdentityCredential), args.Error(1)
}

func (m *MockAzSecretsClient) NewClient(endpoint string, credential *azidentity.WorkloadIdentityCredential, options *azsecrets.ClientOptions) (*azsecrets.Client, error) {
	args := m.Called(endpoint, credential, options)
	return args.Get(0).(*azsecrets.Client), args.Error(1)
}

func TestInitializeKvClient(t *testing.T) {
	mockCredential := new(MockWorkloadIdentityCredential)
	mockSecretsClient := new(MockAzSecretsClient)

	tests := []struct {
		name              string
		kvEndpoint        string
		userAgent         string
		tenantID          string
		clientID          string
		mockCredentialErr error
		mockSecretsErr    error
		expectedErr       bool
	}{
		{
			name:        "Empty user agent",
			kvEndpoint:  "https://test.vault.azure.net",
			userAgent:   "",
			expectedErr: true,
		},
		{
			name:        "Auth failure",
			kvEndpoint:  "https://test.vault.azure.net",
			tenantID:    "testTenantID",
			clientID:    "testClientID",
			expectedErr: true,
		},
		{
			name:              "credential creation error",
			kvEndpoint:        "https://test-keyvault.vault.azure.net",
			tenantID:          "test-tenant-id",
			clientID:          "test-client-id",
			mockCredentialErr: errors.New("failed to create workload identity credential"),
			expectedErr:       true,
		},
		{
			name:           "azsecrets client creation error",
			kvEndpoint:     "https://test-keyvault.vault.azure.net",
			tenantID:       "test-tenant-id",
			clientID:       "test-client-id",
			mockSecretsErr: errors.New("failed to create azsecrets client"),
			expectedErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mocks
			mockCredential.On("NewWorkloadIdentityCredential", mock.Anything).Return(mockCredential, tt.mockCredentialErr)
			mockSecretsClient.On("NewClient", tt.kvEndpoint, mockCredential, mock.Anything).Return(mockSecretsClient, tt.mockSecretsErr)

			// Call function under test
			secretsClient, err := initializeKvClient(tt.kvEndpoint, tt.tenantID, tt.clientID, nil)

			// Validate expectations
			if tt.expectedErr {
				assert.Error(t, err)
				assert.Nil(t, secretsClient)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, secretsClient)
			}
		})
	}
}

func TestInitializeKvClient_Success(t *testing.T) {
	// Mock the context and input parameters
	keyVaultEndpoint := "https://myvault.vault.azure.net/"
	tenantID := "tenant-id"
	clientID := "client-id"

	// Create a mock credential provider
	mockCredential, err := azidentity.NewClientSecretCredential(tenantID, clientID, "fake-secret", nil)
	if err != nil {
		t.Fatalf("Failed to create mock credential: %v", err)
	}

	// Run the function with the mock credential
	kvClientSecrets, err := initializeKvClient(keyVaultEndpoint, tenantID, clientID, mockCredential)

	// Assert the function succeeds without errors and clients are created
	assert.NotNil(t, kvClientSecrets)
	assert.NoError(t, err)
}

func TestGetCertificates(t *testing.T) {
	cases := []struct {
		desc        string
		parameters  map[string]string
		secrets     map[string]string
		expectedErr bool
	}{
		{
			desc:        "keyvault uri not provided",
			parameters:  map[string]string{},
			expectedErr: true,
		},
		{
			desc: "tenantID not provided",
			parameters: map[string]string{
				"vaultUri": "https://testkv.vault.azure.net/",
			},
			expectedErr: true,
		},
		{
			desc: "clientID not provided",
			parameters: map[string]string{
				"vaultUri": "https://testkv.vault.azure.net/",
				"tenantID": "tid",
			},
			expectedErr: true,
		},
		{
			desc: "certificates array not set",
			parameters: map[string]string{
				"vaultUri":             "https://testkv.vault.azure.net/",
				"tenantID":             "tid",
				"useVMManagedIdentity": "true",
			},
			expectedErr: true,
		},
		{
			desc: "certificates not configured as an array",
			parameters: map[string]string{
				"vaultUri":             "https://testkv.vault.azure.net/",
				"tenantID":             "tid",
				"useVMManagedIdentity": "true",
				"certificates": `
        - |
          CertificateName: cert1
          CertificateVersion: ""`,
			},
			expectedErr: true,
		},
		{
			desc: "certificates array is empty",
			parameters: map[string]string{
				"vaultUri": "https://testkv.vault.azure.net/",
				"tenantID": "tid",
				"clientID": "clientid",
				"certificates": `
      array:`,
			},
			expectedErr: true,
		},
		{
			desc: "invalid object format",
			parameters: map[string]string{
				"vaultUri": "https://testkv.vault.azure.net/",
				"tenantID": "tid",
				"clientID": "clientid",
				"certificates": `
      array:
        - |
          CertificateName: cert1
          CertificateVersion: ""`,
			},
			expectedErr: true,
		},
		{
			desc: "error fetching from keyvault",
			parameters: map[string]string{
				"vaultUri": "https://testkv.vault.azure.net/",
				"tenantID": "tid",
				"certificates": `
      array:
        - |
          CertificateName: cert1
          CertificateVersion: ""`,
			},
			expectedErr: true,
		},
	}

	provider := Create()

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			certs, certStatus, err := provider.GetCertificates(context.TODO(), tc.parameters)
			if tc.expectedErr {
				assert.NotNil(t, err)
				assert.Nil(t, certs)
				assert.Nil(t, certStatus)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestGetCertStatusMap(t *testing.T) {
	certsStatus := make([]map[string]string, 0, 2)
	certsStatus = append(certsStatus, map[string]string{
		"CertName":    "Cert1",
		"CertVersion": "VersionABC",
	})
	certsStatus = append(certsStatus, map[string]string{
		"CertName":    "Cert2",
		"CertVersion": "VersionEDF",
	})

	actual := getCertStatusMap(certsStatus)
	assert.NotNil(t, actual[types.CertificatesStatus])
}

func TestGetObjectVersion(t *testing.T) {
	id := "https://kindkv.vault.azure.net/secrets/cert1/c55925c29c6743dcb9bb4bf091be03b0"
	expectedVersion := "c55925c29c6743dcb9bb4bf091be03b0"
	actual := getObjectVersion(id)
	assert.Equal(t, expectedVersion, actual)
}

func TestGetCertStatusProperty(t *testing.T) {
	timeNow := time.Now().String()
	certName := "certName"
	certVersion := "versionABC"

	status := getCertStatusProperty(certName, certVersion, timeNow)
	assert.Equal(t, certName, status[types.CertificateName])
	assert.Equal(t, timeNow, status[types.CertificateLastRefreshed])
	assert.Equal(t, certVersion, status[types.CertificateVersion])
}

func TestGetKeyvaultRequestObj(t *testing.T) {
	attrib := map[string]string{}
	attrib["vaultURI"] = "https://testvault.vault.azure.net/"
	attrib["clientID"] = "TestClient"
	attrib["tenantID"] = "TestIDABC"
	attrib["certificates"] = "array:\n- |\n  certificateName: wabbit-networks-io  \n  certificateVersion: \"testversion\"\n"

	result, err := getKeyvaultRequestObj(context.Background(), attrib)

	if err != nil {
		logrus.Infof("err %v", err)
	}

	assert.Equal(t, "wabbit-networks-io", result[0].CertificateName)
	assert.Equal(t, "testversion", result[0].CertificateVersion)
}

func Test(t *testing.T) {
	cases := []struct {
		desc        string
		value       string
		contentType string
		id          azsecrets.ID
		expectedErr bool
	}{
		{
			desc:        "Pem Content Type",
			value:       "-----BEGIN CERTIFICATE-----\nMIIC8TCCAdmgAwIBAgIUaNrwbhs/I1ecqUYdzD2xuAVNdmowDQYJKoZIhvcNAQEL\nBQAwKjEPMA0GA1UECgwGUmF0aWZ5MRcwFQYDVQQDDA5SYXRpZnkgUm9vdCBDQTAe\nFw0yMzA2MjEwMTIyMzdaFw0yNDA2MjAwMTIyMzdaMBkxFzAVBgNVBAMMDnJhdGlm\neS5kZWZhdWx0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtskG1BUt\n4Fw2lbm53KbwZb1hnLmWdwRotZyznhhk/yrUDcq3uF6klwpk/E2IKfUKIo6doHSk\nXaEZXR68UtXygvA4wdg7xZ6kKpXy0gu+RxGE6CGtDHTyDDzITu+NBjo21ZSsyGpQ\nJeIKftUCHdwdygKf0CdJx8A29GBRpHGCmJadmt7tTzOnYjmbuPVLeqJo/Ex9qXcG\nZbxoxnxr5NCocFeKx+EbLo+k/KjdFB2PKnhgzxAaMMMP6eXPr8l5AlzkC83EmPvN\ntveuaBbamdlFkD+53TZeZlxt3GIdq93Iw/UpbQ/pvhbrztMT+UVEkm15sShfX8Xn\nL2st5A4n0V+66QIDAQABoyAwHjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIH\ngDANBgkqhkiG9w0BAQsFAAOCAQEAGpOqozyfDSBjoTepsRroxxcZ4sq65gw45Bme\nm36BS6FG0WHIg3cMy6KIIBefTDSKrPkKNTtuF25AeGn9jM+26cnfDM78ZH0+Lnn7\n7hs0MA64WMPQaWs9/+89aM9NADV9vp2zdG4xMi6B7DruvKWyhJaNoRqK/qP6LdSQ\nw8M+21sAHvXgrRkQtJlVOzVhgwt36NOb1hzRlQiZB+nhv2Wbw7fbtAaADk3JAumf\nvM+YdPS1KfAFaYefm4yFd+9/C0KOkHico3LTbELO5hG0Mo/EYvtjM+Fljb42EweF\n3nAx1GSPe5Tn8p3h6RyJW5HIKozEKyfDuLS0ccB/nqT3oNjcTw==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIDRTCCAi2gAwIBAgIUcC33VfaMhOnsl7avNTRVQozoVtUwDQYJKoZIhvcNAQEL\nBQAwKjEPMA0GA1UECgwGUmF0aWZ5MRcwFQYDVQQDDA5SYXRpZnkgUm9vdCBDQTAe\nFw0yMzA2MjEwMTIyMzZaFw0yMzA2MjIwMTIyMzZaMCoxDzANBgNVBAoMBlJhdGlm\neTEXMBUGA1UEAwwOUmF0aWZ5IFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB\nDwAwggEKAoIBAQDDFhDnyPrVDZaeRu6Tbg1a/iTwus+IuX+h8aKhKS1yHz4EF/Lz\nxCy7lNSQ9srGMMVumWuNom/ydIphff6PejZM1jFKPU6OQR/0JX5epcVIjbKa562T\nDguUxJ+h5V3EIyM4RqOWQ2g/xZo86x5TzyNJXiVdHHRvmDvUNwPpMeDjr/EHVAni\n5YQObxkJRiiZ7XOa5zz3YztVm8sSZAwPWroY1HIfvtP+KHpiNDIKSymmuJkH4SEr\nJn++iqN8na18a9DFBPTTrLPe3CxATGrMfosCMZ6LP3iFLLc/FaSpwcnugWdewsUK\nYs+sUY7jFWR7x7/1nyFWyRrQviM4f4TY+K7NAgMBAAGjYzBhMB0GA1UdDgQWBBQH\nYePW7QPP2p1utr3r6gqzEkKs+DAfBgNVHSMEGDAWgBQHYePW7QPP2p1utr3r6gqz\nEkKs+DAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDANBgkqhkiG9w0B\nAQsFAAOCAQEAjKp4vx3bFaKVhAbQeTsDjWJgmXLK2vLgt74MiUwSF6t0wehlfszE\nIcJagGJsvs5wKFf91bnwiqwPjmpse/thPNBAxh1uEoh81tOklv0BN790vsVpq3t+\ncnUvWPiCZdRlAiGGFtRmKk3Keq4sM6UdiUki9s+wnxypHVb4wIpVxu5R271Lnp5I\n+rb2EQ48iblt4XZPczf/5QJdTgbItjBNbuO8WVPOqUIhCiFuAQziLtNUq3p81dHO\nQ2BPgmaitCpIUYHVYighLauBGCH8xOFzj4a4KbOxKdxyJTd0La/vRCKaUtJX67Lc\nfQYVR9HXQZ0YlmwPcmIG5v7wBfcW34NUvA==\n-----END CERTIFICATE-----\n",
			contentType: "application/x-pem-file",
			id:          "https://notarycerts.vault.azure.net/secrets/testCert6212/431ad135165741dcb95a46cf3e6686fb",
			expectedErr: false,
		},
		{
			desc:        "PKCS12 Content Type",
			value:       "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",
			contentType: "application/x-pkcs12",
			id:          "https://notarycerts.vault.azure.net/secrets/testCert6212/431ad135165741dcb95a46cf3e6686fb",
			expectedErr: false,
		},
		{
			desc:        "Invalid PKCS12 Content",
			value:       "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",
			contentType: "application/x-pkcs12",
			id:          "https://notarycerts.vault.azure.net/secrets/testCert6212/431ad135165741dcb95a46cf3e6686fb",
			expectedErr: true,
		},
		{
			desc:        "Secret Text File",
			value:       "text",
			contentType: "text",
			id:          "https://notarycerts.vault.azure.net/secrets/testCert6212/431ad135165741dcb95a46cf3e6686fb",
			expectedErr: true,
		},
		{
			desc:        "Test empty",
			value:       "",
			contentType: "",
			id:          "",
			expectedErr: true,
		},
	}

	for i, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			testdata := azsecrets.SecretBundle{
				Value:       &cases[i].value,
				ID:          &cases[i].id,
				ContentType: &cases[i].contentType,
			}

			certs, status, err := getCertsFromSecretBundle(context.Background(), testdata, "certName")
			if tc.expectedErr {
				assert.NotNil(t, err)
				assert.Nil(t, certs)
				assert.Nil(t, status)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestGetKeyvaultRequestObj_error(t *testing.T) {
	cases := []struct {
		desc        string
		attrib      map[string]string
		expectedErr bool
	}{
		{
			desc: "certificates is not set",
			attrib: map[string]string{
				"certificates": "",
			},
			expectedErr: true,
		},
		{
			desc: "unexpected certificate string",
			attrib: map[string]string{
				"certificates": "certificateName: wabbit-networks-io  \n  certificateVersion: \"testversion\"\n",
			},
			expectedErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := getKeyvaultRequestObj(context.Background(), tc.attrib)
			if tc.expectedErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}
