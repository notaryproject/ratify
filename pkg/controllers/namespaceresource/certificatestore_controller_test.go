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

package namespaceresource

import (
	"context"
	"testing"

	configv1beta1 "github.com/notaryproject/ratify/v2/api/v1beta1"
	"github.com/notaryproject/ratify/v2/internal/constants"
	"github.com/notaryproject/ratify/v2/pkg/certificateprovider"
	"github.com/notaryproject/ratify/v2/pkg/certificateprovider/inline"
	"github.com/notaryproject/ratify/v2/pkg/controllers"
	test "github.com/notaryproject/ratify/v2/pkg/utils"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ctxUtils "github.com/notaryproject/ratify/v2/internal/context"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func TestGetCertStoreConfig_ValidConfig(t *testing.T) {
	var parametersString = "{\"certificates\":\"array:\\n  - |\\n    certificateName: wabbit-networks-io\\n    certificateVersion: 97a1545d893344079ce57699c8810590\\n\",\"clientID\":\"sampleClientID\",\"keyvaultName\":\"sampleKeyVault\",\"tenantID\":\"sampleTenantID\"}"
	var certStoreParameters = []byte(parametersString)

	spec := configv1beta1.CertificateStoreSpec{
		Provider: "azurekeyvault",
		Parameters: runtime.RawExtension{
			Raw: certStoreParameters,
		},
	}

	result, err := getCertStoreConfig(spec)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	if len(result) != 4 ||
		result["clientID"] != "sampleClientID" ||
		result["tenantID"] != "sampleTenantID" ||
		result["keyvaultName"] != "sampleKeyVault" ||
		result["certificates"] != "array:\n  - |\n    certificateName: wabbit-networks-io\n    certificateVersion: 97a1545d893344079ce57699c8810590\n" {
		t.Fatalf("unexpected value")
	}
}

func TestGetCertStoreConfig_EmptyStringError(t *testing.T) {
	var parametersString = ""
	var certStoreParameters = []byte(parametersString)

	spec := configv1beta1.CertificateStoreSpec{
		Provider: "azurekeyvault",
		Parameters: runtime.RawExtension{
			Raw: certStoreParameters,
		},
	}

	_, err := getCertStoreConfig(spec)
	if err == nil {
		t.Fatalf("Expected error")
	}

	expectedError := "received empty parameters"
	if err.Error() != expectedError {
		t.Fatalf("Unexpected error, expected %+v, got %+v", expectedError, err.Error())
	}
}

func TestUpdateErrorStatus(t *testing.T) {
	var parametersString = "{\"certs\":{\"name\":\"certName\"}}"
	var certStatus = []byte(parametersString)

	status := configv1beta1.CertificateStoreStatus{
		IsSuccess: true,
		Properties: runtime.RawExtension{
			Raw: certStatus,
		},
	}
	certStore := configv1beta1.CertificateStore{
		Status: status,
	}
	expectedErr := "it's a long error from unit test"
	lastFetchedTime := metav1.Now()
	updateErrorStatus(&certStore, expectedErr, &lastFetchedTime)

	if certStore.Status.IsSuccess != false {
		t.Fatalf("Unexpected error, expected isSuccess to be false , actual %+v", certStore.Status.IsSuccess)
	}

	if certStore.Status.Error != expectedErr {
		t.Fatalf("Unexpected error string, expected %+v, got %+v", expectedErr, certStore.Status.Error)
	}
	if certStore.Status.BriefError != expectedErr {
		t.Fatalf("Unexpected error string, expected %+v, got %+v", expectedErr, certStore.Status.Error)
	}

	//make sure properties of last cached cert was not overridden
	if len(certStore.Status.Properties.Raw) == 0 {
		t.Fatalf("Unexpected properties,  expected %+v, got %+v", parametersString, string(certStore.Status.Properties.Raw))
	}
}

func TestUpdateSuccessStatus(t *testing.T) {
	certStatus := certificateprovider.CertificatesStatus{}
	properties := map[string]string{}
	properties["CertName"] = "wabbit"
	properties["Version"] = "ABC"

	certStatus["Certificates"] = properties

	lastFetchedTime := metav1.Now()

	status := configv1beta1.CertificateStoreStatus{
		IsSuccess: false,
		Error:     "error from last operation",
	}
	certStore := configv1beta1.CertificateStore{
		Status: status,
	}

	updateSuccessStatus(&certStore, &lastFetchedTime, certStatus)

	if certStore.Status.IsSuccess != true {
		t.Fatalf("Expected isSuccess to be true , actual %+v", certStore.Status.IsSuccess)
	}

	if certStore.Status.Error != "" {
		t.Fatalf("Unexpected error string, actual %+v", certStore.Status.Error)
	}

	//make sure properties of last cached cert was updated
	if len(certStore.Status.Properties.Raw) == 0 {
		t.Fatalf("Properties should not be empty")
	}
}

func TestUpdateSuccessStatus_emptyProperties(t *testing.T) {
	lastFetchedTime := metav1.Now()
	status := configv1beta1.CertificateStoreStatus{
		IsSuccess: false,
		Error:     "error from last operation",
	}
	certStore := configv1beta1.CertificateStore{
		Status: status,
	}

	updateSuccessStatus(&certStore, &lastFetchedTime, nil)

	if certStore.Status.IsSuccess != true {
		t.Fatalf("Expected isSuccess to be true , actual %+v", certStore.Status.IsSuccess)
	}

	if certStore.Status.Error != "" {
		t.Fatalf("Unexpected error string, actual %+v", certStore.Status.Error)
	}

	//make sure properties of last cached cert was updated
	if len(certStore.Status.Properties.Raw) != 0 {
		t.Fatalf("Properties should be empty")
	}
}

func TestGetCertificateProvider(t *testing.T) {
	providers := map[string]certificateprovider.CertificateProvider{}
	providers["inline"] = inline.Create()
	result, _ := getCertificateProvider(providers, "inline")

	if result == nil {
		t.Fatalf("Expected getCertificateProvider() to return inline cert provider")
	}

	_, err := getCertificateProvider(providers, "azurekv")
	if err == nil {
		t.Fatalf("Getting unregistered provider should returns an error")
	}
}

func TestCertStoreReconcile(t *testing.T) {
	tests := []struct {
		name              string
		description       string
		provider          *configv1beta1.CertificateStore
		req               *reconcile.Request
		expectedErr       bool
		expectedCertCount int
	}{
		{
			name:        "nonexistent store",
			description: "Reconciling a non-existent certStore CR, it should be deleted from map",
			req: &reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "nonexistent"},
			},
			provider: &configv1beta1.CertificateStore{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testNamespace,
					Name:      storeName,
				},
				Spec: configv1beta1.CertificateStoreSpec{
					Provider: "inline",
				},
			},
			expectedErr:       false,
			expectedCertCount: 0,
		},
		{
			name:        "invalid params",
			description: "Received invalid parameters of the certStore Spec, it should fail the reconcile and return an error",
			provider: &configv1beta1.CertificateStore{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testNamespace,
					Name:      storeName,
				},
				Spec: configv1beta1.CertificateStoreSpec{
					Provider: "inline",
				},
			},
			expectedErr:       true,
			expectedCertCount: 0,
		},
		{
			name:        "valid params",
			description: "Received invalid parameters of the certStore Spec, it should fail the reconcile and return an error",
			provider: &configv1beta1.CertificateStore{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testNamespace,
					Name:      storeName,
				},
				Spec: configv1beta1.CertificateStoreSpec{
					Provider: "inline",
					Parameters: runtime.RawExtension{
						Raw: []byte(`{"value": "-----BEGIN CERTIFICATE-----\nMIID2jCCAsKgAwIBAgIQXy2VqtlhSkiZKAGhsnkjbDANBgkqhkiG9w0BAQsFADBvMRswGQYDVQQD\nExJyYXRpZnkuZXhhbXBsZS5jb20xDzANBgNVBAsTBk15IE9yZzETMBEGA1UEChMKTXkgQ29tcGFu\neTEQMA4GA1UEBxMHUmVkbW9uZDELMAkGA1UECBMCV0ExCzAJBgNVBAYTAlVTMB4XDTIzMDIwMTIy\nNDUwMFoXDTI0MDIwMTIyNTUwMFowbzEbMBkGA1UEAxMScmF0aWZ5LmV4YW1wbGUuY29tMQ8wDQYD\nVQQLEwZNeSBPcmcxEzARBgNVBAoTCk15IENvbXBhbnkxEDAOBgNVBAcTB1JlZG1vbmQxCzAJBgNV\nBAgTAldBMQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL10bM81\npPAyuraORABsOGS8M76Bi7Guwa3JlM1g2D8CuzSfSTaaT6apy9GsccxUvXd5cmiP1ffna5z+EFmc\nizFQh2aq9kWKWXDvKFXzpQuhyqD1HeVlRlF+V0AfZPvGt3VwUUjNycoUU44ctCWmcUQP/KShZev3\n6SOsJ9q7KLjxxQLsUc4mg55eZUThu8mGB8jugtjsnLUYvIWfHhyjVpGrGVrdkDMoMn+u33scOmrt\nsBljvq9WVo4T/VrTDuiOYlAJFMUae2Ptvo0go8XTN3OjLblKeiK4C+jMn9Dk33oGIT9pmX0vrDJV\nX56w/2SejC1AxCPchHaMuhlwMpftBGkCAwEAAaNyMHAwDgYDVR0PAQH/BAQDAgeAMAkGA1UdEwQC\nMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHwYDVR0jBBgwFoAU0eaKkZj+MS9jCp9Dg1zdv3v/aKww\nHQYDVR0OBBYEFNHmipGY/jEvYwqfQ4Nc3b97/2isMA0GCSqGSIb3DQEBCwUAA4IBAQBNDcmSBizF\nmpJlD8EgNcUCy5tz7W3+AAhEbA3vsHP4D/UyV3UgcESx+L+Nye5uDYtTVm3lQejs3erN2BjW+ds+\nXFnpU/pVimd0aYv6mJfOieRILBF4XFomjhrJOLI55oVwLN/AgX6kuC3CJY2NMyJKlTao9oZgpHhs\nLlxB/r0n9JnUoN0Gq93oc1+OLFjPI7gNuPXYOP1N46oKgEmAEmNkP1etFrEjFRgsdIFHksrmlOlD\nIed9RcQ087VLjmuymLgqMTFX34Q3j7XgN2ENwBSnkHotE9CcuGRW+NuiOeJalL8DBmFXXWwHTKLQ\nPp5g6m1yZXylLJaFLKz7tdMmO355\n-----END CERTIFICATE-----\n"}`),
					},
				},
			},
			expectedErr:       false,
			expectedCertCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme, _ := test.CreateScheme()
			client := fake.NewClientBuilder().WithScheme(scheme)
			client.WithObjects(tt.provider)
			r := &CertificateStoreReconciler{
				Scheme: scheme,
				Client: client.Build(),
			}
			var req reconcile.Request
			if tt.req != nil {
				req = *tt.req
			} else {
				req = reconcile.Request{
					NamespacedName: test.KeyFor(tt.provider),
				}
			}

			_, err := r.Reconcile(context.Background(), req)
			if tt.expectedErr != (err != nil) {
				t.Fatalf("Reconcile() expected error %v, actual %v", tt.expectedErr, err)
			}
			ctx := ctxUtils.SetContextWithNamespace(context.Background(), testNamespace)
			certs, _ := controllers.NamespacedCertStores.GetCertsFromStore(ctx, testNamespace+constants.NamespaceSeperator+storeName)
			if len(certs) != tt.expectedCertCount {
				t.Fatalf("Store map expected size %v, actual %v", tt.expectedCertCount, len(certs))
			}
		})
	}
}
