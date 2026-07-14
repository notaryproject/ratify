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
	"errors"
	"fmt"
	"reflect"
	"testing"

	configv1beta1 "github.com/notaryproject/ratify/v2/api/v1beta1"
	re "github.com/notaryproject/ratify/v2/errors"
	kmp "github.com/notaryproject/ratify/v2/pkg/keymanagementprovider"
	"github.com/notaryproject/ratify/v2/pkg/keymanagementprovider/mocks"
	"github.com/notaryproject/ratify/v2/pkg/keymanagementprovider/refresh"
	test "github.com/notaryproject/ratify/v2/pkg/utils"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func init() {
	refresh.Register("mockRefresher", &MockRefresher{})
}

type MockRefresher struct {
	Result       ctrl.Result
	RefreshError bool
	ResultError  bool
	StatusError  bool
	Status       kmp.KeyManagementProviderStatus
}

func (mr *MockRefresher) Refresh(_ context.Context) error {
	if mr.RefreshError {
		return errors.New("error from refresh")
	}
	return nil
}

func (mr *MockRefresher) GetResult() interface{} {
	if mr.ResultError {
		return errors.New("error from result")
	}
	return mr.Result
}

func (mr *MockRefresher) GetStatus() interface{} {
	if mr.StatusError {
		return errors.New("error from status")
	}
	return mr.Status
}

func (mr *MockRefresher) Create(config refresh.RefresherConfig) (refresh.Refresher, error) {
	if config.Resource == "refreshError/test" {
		return &MockRefresher{
			RefreshError: true,
		}, nil
	}
	if config.Resource == "resultError/test" {
		return &MockRefresher{
			ResultError: true,
		}, nil
	}
	if config.Resource == "statusError/test" {
		return &MockRefresher{
			StatusError: true,
		}, nil
	}
	return &MockRefresher{}, nil
}
func TestKeyManagementProviderReconciler_ReconcileWithType(t *testing.T) {
	tests := []struct {
		name              string
		clientGetFunc     func(_ context.Context, key types.NamespacedName, obj client.Object) error
		clientListFunc    func(_ context.Context, list client.ObjectList) error
		resourceNamespace string
		refresherType     string
		expectedResult    ctrl.Result
		expectedError     bool
	}{
		{
			// TODO: Add SetLogger to internal/logger/logger.go to compare log messages
			// https://maxchadwick.xyz/blog/testing-log-output-in-go-logrus
			name: "api is not found",
			clientGetFunc: func(_ context.Context, _ types.NamespacedName, _ client.Object) error {
				resource := schema.GroupResource{
					Group:    "",     // Use an empty string for core resources (like Pod)
					Resource: "pods", // Resource type, e.g., "pods" for Pod resources
				}
				return apierrors.NewNotFound(resource, "test")
			},
			clientListFunc: func(_ context.Context, _ client.ObjectList) error {
				return nil
			},
			resourceNamespace: "test",
			refresherType:     "mockRefresher",
			expectedResult:    ctrl.Result{},
			expectedError:     false,
		},
		{
			name: "unable to fetch key management provider",
			clientGetFunc: func(_ context.Context, _ types.NamespacedName, _ client.Object) error {
				return fmt.Errorf("unable to fetch key management provider")
			},
			clientListFunc: func(_ context.Context, _ client.ObjectList) error {
				return nil
			},
			resourceNamespace: "test",
			refresherType:     "mockRefresher",
			expectedResult:    ctrl.Result{},
			expectedError:     false,
		},
		{
			name: "unable to list certificate stores",
			clientGetFunc: func(_ context.Context, _ types.NamespacedName, _ client.Object) error {
				return nil
			},
			clientListFunc: func(_ context.Context, _ client.ObjectList) error {
				return fmt.Errorf("unable to list certificate stores")
			},
			resourceNamespace: "test",
			refresherType:     "mockRefresher",
			expectedResult:    ctrl.Result{},
			expectedError:     true,
		},
		{
			name: "certificate store already exists",
			clientGetFunc: func(_ context.Context, _ types.NamespacedName, obj client.Object) error {
				getKMP, ok := obj.(*configv1beta1.NamespacedKeyManagementProvider)
				if !ok {
					return errors.New("expected KeyManagementProvider")
				}
				getKMP.ObjectMeta = metav1.ObjectMeta{
					Namespace: "test",
					Name:      "test",
				}
				getKMP.Spec = configv1beta1.NamespacedKeyManagementProviderSpec{
					Type: "inline",
					Parameters: runtime.RawExtension{
						Raw: []byte(`{"type": "inline", "contentType": "certificate", "value": "-----BEGIN CERTIFICATE-----\nMIID2jCCAsKgAwIBAgIQXy2VqtlhSkiZKAGhsnkjbDANBgkqhkiG9w0BAQsFADBvMRswGQYDVQQD\nExJyYXRpZnkuZXhhbXBsZS5jb20xDzANBgNVBAsTBk15IE9yZzETMBEGA1UEChMKTXkgQ29tcGFu\neTEQMA4GA1UEBxMHUmVkbW9uZDELMAkGA1UECBMCV0ExCzAJBgNVBAYTAlVTMB4XDTIzMDIwMTIy\nNDUwMFoXDTI0MDIwMTIyNTUwMFowbzEbMBkGA1UEAxMScmF0aWZ5LmV4YW1wbGUuY29tMQ8wDQYD\nVQQLEwZNeSBPcmcxEzARBgNVBAoTCk15IENvbXBhbnkxEDAOBgNVBAcTB1JlZG1vbmQxCzAJBgNV\nBAgTAldBMQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL10bM81\npPAyuraORABsOGS8M76Bi7Guwa3JlM1g2D8CuzSfSTaaT6apy9GsccxUvXd5cmiP1ffna5z+EFmc\nizFQh2aq9kWKWXDvKFXzpQuhyqD1HeVlRlF+V0AfZPvGt3VwUUjNycoUU44ctCWmcUQP/KShZev3\n6SOsJ9q7KLjxxQLsUc4mg55eZUThu8mGB8jugtjsnLUYvIWfHhyjVpGrGVrdkDMoMn+u33scOmrt\nsBljvq9WVo4T/VrTDuiOYlAJFMUae2Ptvo0go8XTN3OjLblKeiK4C+jMn9Dk33oGIT9pmX0vrDJV\nX56w/2SejC1AxCPchHaMuhlwMpftBGkCAwEAAaNyMHAwDgYDVR0PAQH/BAQDAgeAMAkGA1UdEwQC\nMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHwYDVR0jBBgwFoAU0eaKkZj+MS9jCp9Dg1zdv3v/aKww\nHQYDVR0OBBYEFNHmipGY/jEvYwqfQ4Nc3b97/2isMA0GCSqGSIb3DQEBCwUAA4IBAQBNDcmSBizF\nmpJlD8EgNcUCy5tz7W3+AAhEbA3vsHP4D/UyV3UgcESx+L+Nye5uDYtTVm3lQejs3erN2BjW+ds+\nXFnpU/pVimd0aYv6mJfOieRILBF4XFomjhrJOLI55oVwLN/AgX6kuC3CJY2NMyJKlTao9oZgpHhs\nLlxB/r0n9JnUoN0Gq93oc1+OLFjPI7gNuPXYOP1N46oKgEmAEmNkP1etFrEjFRgsdIFHksrmlOlD\nIed9RcQ087VLjmuymLgqMTFX34Q3j7XgN2ENwBSnkHotE9CcuGRW+NuiOeJalL8DBmFXXWwHTKLQ\nPp5g6m1yZXylLJaFLKz7tdMmO355\n-----END CERTIFICATE-----\n"}`),
					},
				}
				return nil
			},
			clientListFunc: func(_ context.Context, list client.ObjectList) error {
				certStoreList, ok := list.(*configv1beta1.CertificateStoreList)
				if !ok {
					return errors.New("expected CertificateStoreList")
				}

				certStoreList.Items = []configv1beta1.CertificateStore{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "test",
						},
					},
				}
				return nil
			},
			resourceNamespace: "test",
			refresherType:     "mockRefresher",
			expectedResult:    ctrl.Result{},
			expectedError:     false,
		},
		{
			name: "cutils.SpecToKeyManagementProvider failed",
			clientGetFunc: func(_ context.Context, _ types.NamespacedName, obj client.Object) error {
				getKMP, ok := obj.(*configv1beta1.NamespacedKeyManagementProvider)
				if !ok {
					return errors.New("expected KeyManagementProvider")
				}
				getKMP.ObjectMeta = metav1.ObjectMeta{
					Namespace: "test",
					Name:      "test",
				}
				return nil
			},
			clientListFunc: func(_ context.Context, _ client.ObjectList) error {
				return nil
			},
			resourceNamespace: "test",
			refresherType:     "mockRefresher",
			expectedResult:    ctrl.Result{},
			expectedError:     true,
		},
		{
			name: "refresh.CreateRefresherFromConfig failed",
			clientGetFunc: func(_ context.Context, _ types.NamespacedName, obj client.Object) error {
				getKMP, ok := obj.(*configv1beta1.NamespacedKeyManagementProvider)
				if !ok {
					return errors.New("expected KeyManagementProvider")
				}
				getKMP.ObjectMeta = metav1.ObjectMeta{
					Namespace: "test",
					Name:      "test",
				}
				getKMP.Spec = configv1beta1.NamespacedKeyManagementProviderSpec{
					Type: "inline",
					Parameters: runtime.RawExtension{
						Raw: []byte(`{"type": "inline", "contentType": "certificate", "value": "-----BEGIN CERTIFICATE-----\nMIID2jCCAsKgAwIBAgIQXy2VqtlhSkiZKAGhsnkjbDANBgkqhkiG9w0BAQsFADBvMRswGQYDVQQD\nExJyYXRpZnkuZXhhbXBsZS5jb20xDzANBgNVBAsTBk15IE9yZzETMBEGA1UEChMKTXkgQ29tcGFu\neTEQMA4GA1UEBxMHUmVkbW9uZDELMAkGA1UECBMCV0ExCzAJBgNVBAYTAlVTMB4XDTIzMDIwMTIy\nNDUwMFoXDTI0MDIwMTIyNTUwMFowbzEbMBkGA1UEAxMScmF0aWZ5LmV4YW1wbGUuY29tMQ8wDQYD\nVQQLEwZNeSBPcmcxEzARBgNVBAoTCk15IENvbXBhbnkxEDAOBgNVBAcTB1JlZG1vbmQxCzAJBgNV\nBAgTAldBMQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL10bM81\npPAyuraORABsOGS8M76Bi7Guwa3JlM1g2D8CuzSfSTaaT6apy9GsccxUvXd5cmiP1ffna5z+EFmc\nizFQh2aq9kWKWXDvKFXzpQuhyqD1HeVlRlF+V0AfZPvGt3VwUUjNycoUU44ctCWmcUQP/KShZev3\n6SOsJ9q7KLjxxQLsUc4mg55eZUThu8mGB8jugtjsnLUYvIWfHhyjVpGrGVrdkDMoMn+u33scOmrt\nsBljvq9WVo4T/VrTDuiOYlAJFMUae2Ptvo0go8XTN3OjLblKeiK4C+jMn9Dk33oGIT9pmX0vrDJV\nX56w/2SejC1AxCPchHaMuhlwMpftBGkCAwEAAaNyMHAwDgYDVR0PAQH/BAQDAgeAMAkGA1UdEwQC\nMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHwYDVR0jBBgwFoAU0eaKkZj+MS9jCp9Dg1zdv3v/aKww\nHQYDVR0OBBYEFNHmipGY/jEvYwqfQ4Nc3b97/2isMA0GCSqGSIb3DQEBCwUAA4IBAQBNDcmSBizF\nmpJlD8EgNcUCy5tz7W3+AAhEbA3vsHP4D/UyV3UgcESx+L+Nye5uDYtTVm3lQejs3erN2BjW+ds+\nXFnpU/pVimd0aYv6mJfOieRILBF4XFomjhrJOLI55oVwLN/AgX6kuC3CJY2NMyJKlTao9oZgpHhs\nLlxB/r0n9JnUoN0Gq93oc1+OLFjPI7gNuPXYOP1N46oKgEmAEmNkP1etFrEjFRgsdIFHksrmlOlD\nIed9RcQ087VLjmuymLgqMTFX34Q3j7XgN2ENwBSnkHotE9CcuGRW+NuiOeJalL8DBmFXXWwHTKLQ\nPp5g6m1yZXylLJaFLKz7tdMmO355\n-----END CERTIFICATE-----\n"}`),
					},
				}
				return nil
			},
			clientListFunc: func(_ context.Context, _ client.ObjectList) error {
				return nil
			},
			resourceNamespace: "test",
			refresherType:     "invalidRefresher",
			expectedResult:    ctrl.Result{},
			expectedError:     true,
		},
		{
			name: "refresh.Refresh failed",
			clientGetFunc: func(_ context.Context, _ types.NamespacedName, obj client.Object) error {
				getKMP, ok := obj.(*configv1beta1.NamespacedKeyManagementProvider)
				if !ok {
					return errors.New("expected KeyManagementProvider")
				}
				getKMP.ObjectMeta = metav1.ObjectMeta{
					Namespace: "test",
					Name:      "test",
				}
				getKMP.Spec = configv1beta1.NamespacedKeyManagementProviderSpec{
					Type: "inline",
					Parameters: runtime.RawExtension{
						Raw: []byte(`{"type": "inline", "contentType": "certificate", "value": "-----BEGIN CERTIFICATE-----\nMIID2jCCAsKgAwIBAgIQXy2VqtlhSkiZKAGhsnkjbDANBgkqhkiG9w0BAQsFADBvMRswGQYDVQQD\nExJyYXRpZnkuZXhhbXBsZS5jb20xDzANBgNVBAsTBk15IE9yZzETMBEGA1UEChMKTXkgQ29tcGFu\neTEQMA4GA1UEBxMHUmVkbW9uZDELMAkGA1UECBMCV0ExCzAJBgNVBAYTAlVTMB4XDTIzMDIwMTIy\nNDUwMFoXDTI0MDIwMTIyNTUwMFowbzEbMBkGA1UEAxMScmF0aWZ5LmV4YW1wbGUuY29tMQ8wDQYD\nVQQLEwZNeSBPcmcxEzARBgNVBAoTCk15IENvbXBhbnkxEDAOBgNVBAcTB1JlZG1vbmQxCzAJBgNV\nBAgTAldBMQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL10bM81\npPAyuraORABsOGS8M76Bi7Guwa3JlM1g2D8CuzSfSTaaT6apy9GsccxUvXd5cmiP1ffna5z+EFmc\nizFQh2aq9kWKWXDvKFXzpQuhyqD1HeVlRlF+V0AfZPvGt3VwUUjNycoUU44ctCWmcUQP/KShZev3\n6SOsJ9q7KLjxxQLsUc4mg55eZUThu8mGB8jugtjsnLUYvIWfHhyjVpGrGVrdkDMoMn+u33scOmrt\nsBljvq9WVo4T/VrTDuiOYlAJFMUae2Ptvo0go8XTN3OjLblKeiK4C+jMn9Dk33oGIT9pmX0vrDJV\nX56w/2SejC1AxCPchHaMuhlwMpftBGkCAwEAAaNyMHAwDgYDVR0PAQH/BAQDAgeAMAkGA1UdEwQC\nMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHwYDVR0jBBgwFoAU0eaKkZj+MS9jCp9Dg1zdv3v/aKww\nHQYDVR0OBBYEFNHmipGY/jEvYwqfQ4Nc3b97/2isMA0GCSqGSIb3DQEBCwUAA4IBAQBNDcmSBizF\nmpJlD8EgNcUCy5tz7W3+AAhEbA3vsHP4D/UyV3UgcESx+L+Nye5uDYtTVm3lQejs3erN2BjW+ds+\nXFnpU/pVimd0aYv6mJfOieRILBF4XFomjhrJOLI55oVwLN/AgX6kuC3CJY2NMyJKlTao9oZgpHhs\nLlxB/r0n9JnUoN0Gq93oc1+OLFjPI7gNuPXYOP1N46oKgEmAEmNkP1etFrEjFRgsdIFHksrmlOlD\nIed9RcQ087VLjmuymLgqMTFX34Q3j7XgN2ENwBSnkHotE9CcuGRW+NuiOeJalL8DBmFXXWwHTKLQ\nPp5g6m1yZXylLJaFLKz7tdMmO355\n-----END CERTIFICATE-----\n"}`),
					},
				}
				return nil
			},
			clientListFunc: func(_ context.Context, _ client.ObjectList) error {
				return nil
			},
			resourceNamespace: "refreshError",
			refresherType:     "mockRefresher",
			expectedResult:    ctrl.Result{},
			expectedError:     true,
		},
		{
			name: "refresher.GetResult failed",
			clientGetFunc: func(_ context.Context, _ types.NamespacedName, obj client.Object) error {
				getKMP, ok := obj.(*configv1beta1.NamespacedKeyManagementProvider)
				if !ok {
					return errors.New("expected KeyManagementProvider")
				}
				getKMP.ObjectMeta = metav1.ObjectMeta{
					Namespace: "test",
					Name:      "test",
				}
				getKMP.Spec = configv1beta1.NamespacedKeyManagementProviderSpec{
					Type: "inline",
					Parameters: runtime.RawExtension{
						Raw: []byte(`{"type": "inline", "contentType": "certificate", "value": "-----BEGIN CERTIFICATE-----\nMIID2jCCAsKgAwIBAgIQXy2VqtlhSkiZKAGhsnkjbDANBgkqhkiG9w0BAQsFADBvMRswGQYDVQQD\nExJyYXRpZnkuZXhhbXBsZS5jb20xDzANBgNVBAsTBk15IE9yZzETMBEGA1UEChMKTXkgQ29tcGFu\neTEQMA4GA1UEBxMHUmVkbW9uZDELMAkGA1UECBMCV0ExCzAJBgNVBAYTAlVTMB4XDTIzMDIwMTIy\nNDUwMFoXDTI0MDIwMTIyNTUwMFowbzEbMBkGA1UEAxMScmF0aWZ5LmV4YW1wbGUuY29tMQ8wDQYD\nVQQLEwZNeSBPcmcxEzARBgNVBAoTCk15IENvbXBhbnkxEDAOBgNVBAcTB1JlZG1vbmQxCzAJBgNV\nBAgTAldBMQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL10bM81\npPAyuraORABsOGS8M76Bi7Guwa3JlM1g2D8CuzSfSTaaT6apy9GsccxUvXd5cmiP1ffna5z+EFmc\nizFQh2aq9kWKWXDvKFXzpQuhyqD1HeVlRlF+V0AfZPvGt3VwUUjNycoUU44ctCWmcUQP/KShZev3\n6SOsJ9q7KLjxxQLsUc4mg55eZUThu8mGB8jugtjsnLUYvIWfHhyjVpGrGVrdkDMoMn+u33scOmrt\nsBljvq9WVo4T/VrTDuiOYlAJFMUae2Ptvo0go8XTN3OjLblKeiK4C+jMn9Dk33oGIT9pmX0vrDJV\nX56w/2SejC1AxCPchHaMuhlwMpftBGkCAwEAAaNyMHAwDgYDVR0PAQH/BAQDAgeAMAkGA1UdEwQC\nMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHwYDVR0jBBgwFoAU0eaKkZj+MS9jCp9Dg1zdv3v/aKww\nHQYDVR0OBBYEFNHmipGY/jEvYwqfQ4Nc3b97/2isMA0GCSqGSIb3DQEBCwUAA4IBAQBNDcmSBizF\nmpJlD8EgNcUCy5tz7W3+AAhEbA3vsHP4D/UyV3UgcESx+L+Nye5uDYtTVm3lQejs3erN2BjW+ds+\nXFnpU/pVimd0aYv6mJfOieRILBF4XFomjhrJOLI55oVwLN/AgX6kuC3CJY2NMyJKlTao9oZgpHhs\nLlxB/r0n9JnUoN0Gq93oc1+OLFjPI7gNuPXYOP1N46oKgEmAEmNkP1etFrEjFRgsdIFHksrmlOlD\nIed9RcQ087VLjmuymLgqMTFX34Q3j7XgN2ENwBSnkHotE9CcuGRW+NuiOeJalL8DBmFXXWwHTKLQ\nPp5g6m1yZXylLJaFLKz7tdMmO355\n-----END CERTIFICATE-----\n"}`),
					},
				}
				return nil
			},
			clientListFunc: func(_ context.Context, _ client.ObjectList) error {
				return nil
			},
			resourceNamespace: "resultError",
			refresherType:     "mockRefresher",
			expectedResult:    ctrl.Result{},
			expectedError:     true,
		},
		{
			name: "refresher.GetStatus failed",
			clientGetFunc: func(_ context.Context, _ types.NamespacedName, obj client.Object) error {
				getKMP, ok := obj.(*configv1beta1.NamespacedKeyManagementProvider)
				if !ok {
					return errors.New("expected KeyManagementProvider")
				}
				getKMP.ObjectMeta = metav1.ObjectMeta{
					Namespace: "test",
					Name:      "test",
				}
				getKMP.Spec = configv1beta1.NamespacedKeyManagementProviderSpec{
					Type: "inline",
					Parameters: runtime.RawExtension{
						Raw: []byte(`{"type": "inline", "contentType": "certificate", "value": "-----BEGIN CERTIFICATE-----\nMIID2jCCAsKgAwIBAgIQXy2VqtlhSkiZKAGhsnkjbDANBgkqhkiG9w0BAQsFADBvMRswGQYDVQQD\nExJyYXRpZnkuZXhhbXBsZS5jb20xDzANBgNVBAsTBk15IE9yZzETMBEGA1UEChMKTXkgQ29tcGFu\neTEQMA4GA1UEBxMHUmVkbW9uZDELMAkGA1UECBMCV0ExCzAJBgNVBAYTAlVTMB4XDTIzMDIwMTIy\nNDUwMFoXDTI0MDIwMTIyNTUwMFowbzEbMBkGA1UEAxMScmF0aWZ5LmV4YW1wbGUuY29tMQ8wDQYD\nVQQLEwZNeSBPcmcxEzARBgNVBAoTCk15IENvbXBhbnkxEDAOBgNVBAcTB1JlZG1vbmQxCzAJBgNV\nBAgTAldBMQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL10bM81\npPAyuraORABsOGS8M76Bi7Guwa3JlM1g2D8CuzSfSTaaT6apy9GsccxUvXd5cmiP1ffna5z+EFmc\nizFQh2aq9kWKWXDvKFXzpQuhyqD1HeVlRlF+V0AfZPvGt3VwUUjNycoUU44ctCWmcUQP/KShZev3\n6SOsJ9q7KLjxxQLsUc4mg55eZUThu8mGB8jugtjsnLUYvIWfHhyjVpGrGVrdkDMoMn+u33scOmrt\nsBljvq9WVo4T/VrTDuiOYlAJFMUae2Ptvo0go8XTN3OjLblKeiK4C+jMn9Dk33oGIT9pmX0vrDJV\nX56w/2SejC1AxCPchHaMuhlwMpftBGkCAwEAAaNyMHAwDgYDVR0PAQH/BAQDAgeAMAkGA1UdEwQC\nMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHwYDVR0jBBgwFoAU0eaKkZj+MS9jCp9Dg1zdv3v/aKww\nHQYDVR0OBBYEFNHmipGY/jEvYwqfQ4Nc3b97/2isMA0GCSqGSIb3DQEBCwUAA4IBAQBNDcmSBizF\nmpJlD8EgNcUCy5tz7W3+AAhEbA3vsHP4D/UyV3UgcESx+L+Nye5uDYtTVm3lQejs3erN2BjW+ds+\nXFnpU/pVimd0aYv6mJfOieRILBF4XFomjhrJOLI55oVwLN/AgX6kuC3CJY2NMyJKlTao9oZgpHhs\nLlxB/r0n9JnUoN0Gq93oc1+OLFjPI7gNuPXYOP1N46oKgEmAEmNkP1etFrEjFRgsdIFHksrmlOlD\nIed9RcQ087VLjmuymLgqMTFX34Q3j7XgN2ENwBSnkHotE9CcuGRW+NuiOeJalL8DBmFXXWwHTKLQ\nPp5g6m1yZXylLJaFLKz7tdMmO355\n-----END CERTIFICATE-----\n"}`),
					},
				}
				return nil
			},
			clientListFunc: func(_ context.Context, _ client.ObjectList) error {
				return nil
			},
			resourceNamespace: "statusError",
			refresherType:     "mockRefresher",
			expectedResult:    ctrl.Result{},
			expectedError:     true,
		},
		{
			name: "successfully reconciled",
			clientGetFunc: func(_ context.Context, _ types.NamespacedName, obj client.Object) error {
				getKMP, ok := obj.(*configv1beta1.NamespacedKeyManagementProvider)
				if !ok {
					return errors.New("expected KeyManagementProvider")
				}
				getKMP.ObjectMeta = metav1.ObjectMeta{
					Namespace: "test",
					Name:      "test",
				}
				getKMP.Spec = configv1beta1.NamespacedKeyManagementProviderSpec{
					Type: "inline",
					Parameters: runtime.RawExtension{
						Raw: []byte(`{"type": "inline", "contentType": "certificate", "value": "-----BEGIN CERTIFICATE-----\nMIID2jCCAsKgAwIBAgIQXy2VqtlhSkiZKAGhsnkjbDANBgkqhkiG9w0BAQsFADBvMRswGQYDVQQD\nExJyYXRpZnkuZXhhbXBsZS5jb20xDzANBgNVBAsTBk15IE9yZzETMBEGA1UEChMKTXkgQ29tcGFu\neTEQMA4GA1UEBxMHUmVkbW9uZDELMAkGA1UECBMCV0ExCzAJBgNVBAYTAlVTMB4XDTIzMDIwMTIy\nNDUwMFoXDTI0MDIwMTIyNTUwMFowbzEbMBkGA1UEAxMScmF0aWZ5LmV4YW1wbGUuY29tMQ8wDQYD\nVQQLEwZNeSBPcmcxEzARBgNVBAoTCk15IENvbXBhbnkxEDAOBgNVBAcTB1JlZG1vbmQxCzAJBgNV\nBAgTAldBMQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL10bM81\npPAyuraORABsOGS8M76Bi7Guwa3JlM1g2D8CuzSfSTaaT6apy9GsccxUvXd5cmiP1ffna5z+EFmc\nizFQh2aq9kWKWXDvKFXzpQuhyqD1HeVlRlF+V0AfZPvGt3VwUUjNycoUU44ctCWmcUQP/KShZev3\n6SOsJ9q7KLjxxQLsUc4mg55eZUThu8mGB8jugtjsnLUYvIWfHhyjVpGrGVrdkDMoMn+u33scOmrt\nsBljvq9WVo4T/VrTDuiOYlAJFMUae2Ptvo0go8XTN3OjLblKeiK4C+jMn9Dk33oGIT9pmX0vrDJV\nX56w/2SejC1AxCPchHaMuhlwMpftBGkCAwEAAaNyMHAwDgYDVR0PAQH/BAQDAgeAMAkGA1UdEwQC\nMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHwYDVR0jBBgwFoAU0eaKkZj+MS9jCp9Dg1zdv3v/aKww\nHQYDVR0OBBYEFNHmipGY/jEvYwqfQ4Nc3b97/2isMA0GCSqGSIb3DQEBCwUAA4IBAQBNDcmSBizF\nmpJlD8EgNcUCy5tz7W3+AAhEbA3vsHP4D/UyV3UgcESx+L+Nye5uDYtTVm3lQejs3erN2BjW+ds+\nXFnpU/pVimd0aYv6mJfOieRILBF4XFomjhrJOLI55oVwLN/AgX6kuC3CJY2NMyJKlTao9oZgpHhs\nLlxB/r0n9JnUoN0Gq93oc1+OLFjPI7gNuPXYOP1N46oKgEmAEmNkP1etFrEjFRgsdIFHksrmlOlD\nIed9RcQ087VLjmuymLgqMTFX34Q3j7XgN2ENwBSnkHotE9CcuGRW+NuiOeJalL8DBmFXXWwHTKLQ\nPp5g6m1yZXylLJaFLKz7tdMmO355\n-----END CERTIFICATE-----\n"}`),
					},
				}
				return nil
			},
			clientListFunc: func(_ context.Context, _ client.ObjectList) error {
				return nil
			},
			resourceNamespace: "test",
			refresherType:     "mockRefresher",
			expectedResult:    ctrl.Result{},
			expectedError:     false,
		},
	}

	for _, tt := range tests {
		fmt.Println(tt.name)
		mockClient := mocks.TestClient{
			GetFunc:  tt.clientGetFunc,
			ListFunc: tt.clientListFunc,
		}
		req := ctrl.Request{
			NamespacedName: client.ObjectKey{
				Name:      "test",
				Namespace: tt.resourceNamespace,
			},
		}
		scheme, _ := test.CreateScheme()

		r := &KeyManagementProviderReconciler{
			Client: &mockClient,
			Scheme: scheme,
		}

		result, err := r.ReconcileWithType(context.Background(), req, tt.refresherType)

		if !reflect.DeepEqual(result, tt.expectedResult) {
			t.Fatalf("Expected result %v, got %v", tt.expectedResult, result)
		}
		if tt.expectedError && err == nil {
			t.Fatalf("Expected error, got nil")
		}
	}
}

func TestKeyManagementProviderReconciler_Reconcile(t *testing.T) {
	req := ctrl.Request{
		NamespacedName: client.ObjectKey{
			Name:      "fake-name",
			Namespace: "fake-namespace",
		},
	}

	// Create a fake client and scheme
	scheme, _ := test.CreateScheme()
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	r := &KeyManagementProviderReconciler{
		Client: client,
		Scheme: runtime.NewScheme(),
	}

	// Call the Reconcile method
	result, err := r.Reconcile(context.TODO(), req)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Check the result
	expectedResult := ctrl.Result{}
	if !reflect.DeepEqual(result, expectedResult) {
		t.Errorf("Expected result %v, got %v", expectedResult, result)
	}
}
func TestKMProviderUpdateErrorStatusNamespaced(t *testing.T) {
	var parametersString = "{\"certs\":{\"name\":\"certName\"}}"
	var kmProviderStatus = []byte(parametersString)

	status := configv1beta1.NamespacedKeyManagementProviderStatus{
		IsSuccess: true,
		Properties: runtime.RawExtension{
			Raw: kmProviderStatus,
		},
	}
	keyManagementProvider := configv1beta1.NamespacedKeyManagementProvider{
		Status: status,
	}
	expectedErr := re.ErrorCodeUnknown.WithDetail("it's a long error from unit test")
	lastFetchedTime := metav1.Now()
	updateKMProviderErrorStatusNamespaced(&keyManagementProvider, &expectedErr, &lastFetchedTime)

	if keyManagementProvider.Status.IsSuccess != false {
		t.Fatalf("Unexpected error, expected isSuccess to be false , actual %+v", keyManagementProvider.Status.IsSuccess)
	}

	if keyManagementProvider.Status.Error != expectedErr.Error() {
		t.Fatalf("Unexpected error string, expected %+v, got %+v", expectedErr, keyManagementProvider.Status.Error)
	}
	if keyManagementProvider.Status.BriefError != expectedErr.GetConciseError(150) {
		t.Fatalf("Unexpected error string, expected %+v, got %+v", expectedErr.GetConciseError(150), keyManagementProvider.Status.Error)
	}

	//make sure properties of last cached cert was not overridden
	if len(keyManagementProvider.Status.Properties.Raw) == 0 {
		t.Fatalf("Unexpected properties,  expected %+v, got %+v", parametersString, string(keyManagementProvider.Status.Properties.Raw))
	}
}

func TestKMProviderUpdateSuccessStatusNamespaced(t *testing.T) {
	kmProviderStatus := kmp.KeyManagementProviderStatus{}
	properties := map[string]string{}
	properties["Name"] = "wabbit"
	properties["Version"] = "ABC"

	kmProviderStatus["Certificates"] = properties

	lastFetchedTime := metav1.Now()

	status := configv1beta1.NamespacedKeyManagementProviderStatus{
		IsSuccess: false,
		Error:     "error from last operation",
	}
	keyManagementProvider := configv1beta1.NamespacedKeyManagementProvider{
		Status: status,
	}

	updateKMProviderSuccessStatusNamespaced(&keyManagementProvider, &lastFetchedTime, kmProviderStatus)

	if keyManagementProvider.Status.IsSuccess != true {
		t.Fatalf("Expected isSuccess to be true , actual %+v", keyManagementProvider.Status.IsSuccess)
	}

	if keyManagementProvider.Status.Error != "" {
		t.Fatalf("Unexpected error string, actual %+v", keyManagementProvider.Status.Error)
	}

	//make sure properties of last cached cert was updated
	if len(keyManagementProvider.Status.Properties.Raw) == 0 {
		t.Fatalf("Properties should not be empty")
	}
}

func TestKMProviderUpdateSuccessStatusNamespaced_emptyProperties(t *testing.T) {
	lastFetchedTime := metav1.Now()
	status := configv1beta1.NamespacedKeyManagementProviderStatus{
		IsSuccess: false,
		Error:     "error from last operation",
	}
	keyManagementProvider := configv1beta1.NamespacedKeyManagementProvider{
		Status: status,
	}

	updateKMProviderSuccessStatusNamespaced(&keyManagementProvider, &lastFetchedTime, nil)

	if keyManagementProvider.Status.IsSuccess != true {
		t.Fatalf("Expected isSuccess to be true , actual %+v", keyManagementProvider.Status.IsSuccess)
	}

	if keyManagementProvider.Status.Error != "" {
		t.Fatalf("Unexpected error string, actual %+v", keyManagementProvider.Status.Error)
	}

	//make sure properties of last cached cert was updated
	if len(keyManagementProvider.Status.Properties.Raw) != 0 {
		t.Fatalf("Properties should be empty")
	}
}

func TestWriteKMProviderStatusNamespaced(t *testing.T) {
	logger := logrus.WithContext(context.Background())
	lastFetchedTime := metav1.Now()
	testCases := []struct {
		name              string
		isSuccess         bool
		kmProvider        *configv1beta1.NamespacedKeyManagementProvider
		errString         string
		expectedErrString string
		reconciler        client.StatusClient
	}{
		{
			name:       "success status",
			isSuccess:  true,
			errString:  "",
			kmProvider: &configv1beta1.NamespacedKeyManagementProvider{},
			reconciler: &test.MockStatusClient{},
		},
		{
			name:              "error status",
			isSuccess:         false,
			kmProvider:        &configv1beta1.NamespacedKeyManagementProvider{},
			errString:         "a long error string that exceeds the max length of 30 characters",
			expectedErrString: "UNKNOWN: a long error string that exceeds the max length of 30 characters",
			reconciler:        &test.MockStatusClient{},
		},
		{
			name:       "status update failed",
			isSuccess:  true,
			kmProvider: &configv1beta1.NamespacedKeyManagementProvider{},
			reconciler: &test.MockStatusClient{
				UpdateFailed: true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := re.ErrorCodeUnknown.WithDetail(tc.errString)
			writeKMProviderStatusNamespaced(context.Background(), tc.reconciler, tc.kmProvider, logger, tc.isSuccess, &err, lastFetchedTime, nil)

			if tc.kmProvider.Status.IsSuccess != tc.isSuccess {
				t.Fatalf("Expected isSuccess to be %+v , actual %+v", tc.isSuccess, tc.kmProvider.Status.IsSuccess)
			}

			if tc.kmProvider.Status.Error != tc.expectedErrString {
				t.Fatalf("Expected Error to be %+v , actual %+v", tc.expectedErrString, tc.kmProvider.Status.Error)
			}
		})
	}
}
