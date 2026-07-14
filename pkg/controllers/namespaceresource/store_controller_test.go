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
	"os"
	"strings"
	"testing"

	configv1beta1 "github.com/notaryproject/ratify/v2/api/v1beta1"
	re "github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/pkg/controllers"
	"github.com/notaryproject/ratify/v2/pkg/customresources/referrerstores"
	test "github.com/notaryproject/ratify/v2/pkg/utils"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	storeName  = "testStore"
	sampleName = "sample"
	orasName   = "oras"
)

func TestStoreAdd_EmptyParameter(t *testing.T) {
	resetStoreMap()
	dirPath, err := test.CreatePlugin(sampleName)
	if err != nil {
		t.Fatalf("createPlugin() expected no error, actual %v", err)
	}
	defer os.RemoveAll(dirPath)

	var testStoreSpec = configv1beta1.NamespacedStoreSpec{
		Name:    sampleName,
		Address: dirPath,
	}

	if err := storeAddOrReplace(testStoreSpec, "oras", testNamespace); err != nil {
		t.Fatalf("storeAddOrReplace() expected no error, actual %v", err)
	}
	if len(controllers.NamespacedStores.GetStores(testNamespace)) != 1 {
		t.Fatalf("Store map expected size 1, actual %v", len(controllers.NamespacedStores.GetStores(testNamespace)))
	}
}

func TestStoreAdd_InvalidConfig(t *testing.T) {
	resetStoreMap()
	var testStoreSpec = configv1beta1.NamespacedStoreSpec{
		Name: orasName,
		Parameters: runtime.RawExtension{
			Raw: []byte("test"),
		},
	}

	if err := storeAddOrReplace(testStoreSpec, orasName, testNamespace); err == nil {
		t.Fatalf("storeAddOrReplace() expected error, actual %v", err)
	}
	if len(controllers.NamespacedStores.GetStores(testNamespace)) != 0 {
		t.Fatalf("Store map expected size 0, actual %v", len(controllers.NamespacedStores.GetStores(testNamespace)))
	}
}

func TestStoreAdd_WithParameters(t *testing.T) {
	resetStoreMap()
	if len(controllers.NamespacedStores.GetStores(testNamespace)) != 0 {
		t.Fatalf("Store map expected size 0, actual %v", len(controllers.NamespacedStores.GetStores(testNamespace)))
	}
	dirPath, err := test.CreatePlugin(sampleName)
	if err != nil {
		t.Fatalf("createPlugin() expected no error, actual %v", err)
	}
	defer os.RemoveAll(dirPath)

	var testStoreSpec = getOrasStoreSpec(sampleName, dirPath)

	if err := storeAddOrReplace(testStoreSpec, "testObject", testNamespace); err != nil {
		t.Fatalf("storeAddOrReplace() expected no error, actual %v", err)
	}
	if len(controllers.NamespacedStores.GetStores(testNamespace)) != 1 {
		t.Fatalf("Store map expected size 1, actual %v", len(controllers.NamespacedStores.GetStores(testNamespace)))
	}
}

func TestStoreAddOrReplace_PluginNotFound(t *testing.T) {
	resetStoreMap()
	var resource = "invalidplugin"
	expectedMsg := "plugin not found"
	var spec = getInvalidStoreSpec()
	err := storeAddOrReplace(spec, resource, testNamespace)

	if !strings.Contains(err.Error(), expectedMsg) {
		t.Fatalf("TestStoreAddOrReplace_PluginNotFound expected msg: '%v', actual %v", expectedMsg, err.Error())
	}
}

func TestWriteStoreStatus(t *testing.T) {
	logger := logrus.WithContext(context.Background())
	testCases := []struct {
		name       string
		isSuccess  bool
		store      *configv1beta1.NamespacedStore
		errString  string
		reconciler client.StatusClient
	}{
		{
			name:       "success status",
			isSuccess:  true,
			store:      &configv1beta1.NamespacedStore{},
			reconciler: &test.MockStatusClient{},
		},
		{
			name:       "error status",
			isSuccess:  false,
			store:      &configv1beta1.NamespacedStore{},
			errString:  "a long error string that exceeds the max length of 30 characters",
			reconciler: &test.MockStatusClient{},
		},
		{
			name:      "status update failed",
			isSuccess: true,
			store:     &configv1beta1.NamespacedStore{},
			reconciler: &test.MockStatusClient{
				UpdateFailed: true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(_ *testing.T) {
			err := re.ErrorCodeUnknown.WithDetail(tc.errString)
			writeStoreStatus(context.Background(), tc.reconciler, tc.store, logger, tc.isSuccess, &err)
		})
	}
}

func TestStore_UpdateAndDelete(t *testing.T) {
	resetStoreMap()
	dirPath, err := test.CreatePlugin(sampleName)
	if err != nil {
		t.Fatalf("createPlugin() expected no error, actual %v", err)
	}
	defer os.RemoveAll(dirPath)

	var testStoreSpec = getOrasStoreSpec(sampleName, dirPath)
	// add a Store
	if err := storeAddOrReplace(testStoreSpec, sampleName, testNamespace); err != nil {
		t.Fatalf("storeAddOrReplace() expected no error, actual %v", err)
	}
	if len(controllers.NamespacedStores.GetStores(testNamespace)) != 1 {
		t.Fatalf("Store map expected size 1, actual %v", len(controllers.NamespacedStores.GetStores(testNamespace)))
	}

	// modify the Store
	var updatedSpec = configv1beta1.NamespacedStoreSpec{
		Name:    sampleName,
		Address: dirPath,
	}

	if err := storeAddOrReplace(updatedSpec, sampleName, testNamespace); err != nil {
		t.Fatalf("storeAddOrReplace() expected no error, actual %v", err)
	}

	// validate no Store has been added
	if len(controllers.NamespacedStores.GetStores(testNamespace)) != 1 {
		t.Fatalf("Store map should be 1 after replacement, actual %v", len(controllers.NamespacedStores.GetStores(testNamespace)))
	}

	controllers.NamespacedStores.DeleteStore(testNamespace, sampleName)

	if len(controllers.NamespacedStores.GetStores(testNamespace)) != 0 {
		t.Fatalf("Store map should be 0 after deletion, actual %v", len(controllers.NamespacedStores.GetStores(testNamespace)))
	}
}

func TestStoreReconcile(t *testing.T) {
	dirPath, err := test.CreatePlugin(orasName)
	if err != nil {
		t.Fatalf("createPlugin() expected no error, actual %v", err)
	}
	defer os.RemoveAll(dirPath)

	tests := []struct {
		name               string
		store              *configv1beta1.NamespacedStore
		req                *reconcile.Request
		expectedErr        bool
		expectedStoreCount int
	}{
		{
			name: "nonexistent store",
			req: &reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "nonexistent"},
			},
			store: &configv1beta1.NamespacedStore{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testNamespace,
					Name:      storeName,
				},
				Spec: configv1beta1.NamespacedStoreSpec{
					Name: orasName,
				},
			},
			expectedErr:        false,
			expectedStoreCount: 0,
		},
		{
			name: "valid spec",
			store: &configv1beta1.NamespacedStore{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testNamespace,
					Name:      storeName,
				},
				Spec: configv1beta1.NamespacedStoreSpec{
					Name:    orasName,
					Address: dirPath,
				},
			},
			expectedErr:        false,
			expectedStoreCount: 1,
		},
		{
			name: "invalid parameters",
			store: &configv1beta1.NamespacedStore{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testNamespace,
					Name:      storeName,
				},
				Spec: configv1beta1.NamespacedStoreSpec{
					Parameters: runtime.RawExtension{
						Raw: []byte("test"),
					},
				},
			},
			expectedErr:        true,
			expectedStoreCount: 0,
		},
		{
			name: "unsupported store",
			store: &configv1beta1.NamespacedStore{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testNamespace,
					Name:      storeName,
				},
				Spec: configv1beta1.NamespacedStoreSpec{
					Name:    "unsupported",
					Address: dirPath,
				},
			},
			expectedErr:        true,
			expectedStoreCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetStoreMap()
			scheme, _ := test.CreateScheme()
			client := fake.NewClientBuilder().WithScheme(scheme)
			client.WithObjects(tt.store)
			r := &StoreReconciler{
				Scheme: scheme,
				Client: client.Build(),
			}
			var req reconcile.Request
			if tt.req != nil {
				req = *tt.req
			} else {
				req = reconcile.Request{
					NamespacedName: test.KeyFor(tt.store),
				}
			}

			_, err := r.Reconcile(context.Background(), req)
			if tt.expectedErr != (err != nil) {
				t.Fatalf("Reconcile() expected error %v, actual %v", tt.expectedErr, err)
			}
			if len(controllers.NamespacedStores.GetStores(testNamespace)) != tt.expectedStoreCount {
				t.Fatalf("Store map expected size %v, actual %v", tt.expectedStoreCount, len(controllers.NamespacedStores.GetStores(testNamespace)))
			}
		})
	}
}

func resetStoreMap() {
	controllers.NamespacedStores = referrerstores.NewActiveStores()
}

func getOrasStoreSpec(pluginName, pluginPath string) configv1beta1.NamespacedStoreSpec {
	var parametersString = "{\"authProvider\":{\"name\":\"k8Secrets\",\"secrets\":[{\"secretName\":\"myregistrykey\"}]},\"cosignEnabled\":false,\"useHttp\":false}"
	var storeParameters = []byte(parametersString)

	return configv1beta1.NamespacedStoreSpec{
		Name:    pluginName,
		Address: pluginPath,
		Parameters: runtime.RawExtension{
			Raw: storeParameters,
		},
	}
}

func getInvalidStoreSpec() configv1beta1.NamespacedStoreSpec {
	return configv1beta1.NamespacedStoreSpec{
		Name:    "pluginnotfound",
		Address: "test/path",
	}
}
