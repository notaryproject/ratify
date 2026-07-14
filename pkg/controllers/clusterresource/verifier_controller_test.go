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

package clusterresource

import (
	"context"
	"errors"
	"os"
	"testing"

	configv1beta1 "github.com/notaryproject/ratify/v2/api/v1beta1"
	re "github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/internal/constants"
	"github.com/notaryproject/ratify/v2/pkg/controllers"
	"github.com/notaryproject/ratify/v2/pkg/customresources/verifiers"
	"github.com/notaryproject/ratify/v2/pkg/utils"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type mockResourceWriter struct {
	updateFailed bool
}

func (w mockResourceWriter) Create(_ context.Context, _ client.Object, _ client.Object, _ ...client.SubResourceCreateOption) error {
	return nil
}

func (w mockResourceWriter) Update(_ context.Context, _ client.Object, _ ...client.SubResourceUpdateOption) error {
	if w.updateFailed {
		return errors.New("update failed")
	}
	return nil
}

func (w mockResourceWriter) Patch(_ context.Context, _ client.Object, _ client.Patch, _ ...client.SubResourcePatchOption) error {
	return nil
}

type mockStatusClient struct {
	updateFailed bool
}

func (c mockStatusClient) Status() client.SubResourceWriter {
	writer := mockResourceWriter{}
	writer.updateFailed = c.updateFailed
	return writer
}

const (
	licenseChecker = "licensechecker"
	verifierName   = "verifierName"
)

func TestMain(m *testing.M) {
	// make sure to reset verifierMap before each test run
	controllers.NamespacedVerifiers = verifiers.NewActiveVerifiers()
	code := m.Run()
	os.Exit(code)
}

func TestVerifierAdd_EmptyParameter(t *testing.T) {
	resetVerifierMap()
	dirPath, err := utils.CreatePlugin(sampleName)
	if err != nil {
		t.Fatalf("createPlugin() expected no error, actual %v", err)
	}
	defer os.RemoveAll(dirPath)

	var testVerifierSpec = configv1beta1.VerifierSpec{
		Name:          sampleName,
		ArtifactTypes: "application/vnd.cncf.notary.signature",
		Address:       dirPath,
	}

	if err := verifierAddOrReplace(testVerifierSpec, sampleName); err != nil {
		t.Fatalf("verifierAddOrReplace() expected no error, actual %v", err)
	}
	if len(controllers.NamespacedVerifiers.GetVerifiers(constants.EmptyNamespace)) != 1 {
		t.Fatalf("Verifier map expected size 1, actual %v", len(controllers.NamespacedVerifiers.GetVerifiers(constants.EmptyNamespace)))
	}
}

func TestVerifierAdd_WithParameters(t *testing.T) {
	resetVerifierMap()
	if len(controllers.NamespacedVerifiers.GetVerifiers(constants.EmptyNamespace)) != 0 {
		t.Fatalf("Verifier map expected size 0, actual %v", len(controllers.NamespacedVerifiers.GetVerifiers(constants.EmptyNamespace)))
	}

	dirPath, err := utils.CreatePlugin(licenseChecker)
	if err != nil {
		t.Fatalf("createPlugin() expected no error, actual %v", err)
	}
	defer os.RemoveAll(dirPath)

	var testVerifierSpec = getDefaultLicenseCheckerSpec(dirPath)

	if err := verifierAddOrReplace(testVerifierSpec, "testObject"); err != nil {
		t.Fatalf("verifierAddOrReplace() expected no error, actual %v", err)
	}
	if len(controllers.NamespacedVerifiers.GetVerifiers(constants.EmptyNamespace)) != 1 {
		t.Fatalf("Verifier map expected size 1, actual %v", len(controllers.NamespacedVerifiers.GetVerifiers(constants.EmptyNamespace)))
	}
}

func TestVerifierAddOrReplace_PluginNotFound(t *testing.T) {
	resetVerifierMap()
	resource := "invalidplugin"
	expectedMsg := "PLUGIN_NOT_FOUND: Verifier plugin pluginnotfound not found: failed to find plugin \"pluginnotfound\" in paths [test/path]: Please ensure that the correct type is specified for the built-in Verifier configuration or the custom Verifier plugin is configured."
	var testVerifierSpec = getInvalidVerifierSpec()
	err := verifierAddOrReplace(testVerifierSpec, resource)

	if err.Error() != expectedMsg {
		t.Fatalf("TestVerifierAddOrReplace_PluginNotFound expected msg: '%v', actual %v", expectedMsg, err.Error())
	}
}

func TestVerifierAdd_InvalidConfig(t *testing.T) {
	resetVerifierMap()
	var testVerifierSpec = configv1beta1.VerifierSpec{
		Name:          "notation",
		ArtifactTypes: "application/vnd.cncf.notary.signature",
		Parameters: runtime.RawExtension{
			Raw: []byte("test\n"),
		},
	}
	var resource = "notation"

	if err := verifierAddOrReplace(testVerifierSpec, resource); err == nil {
		t.Fatalf("Expected an error but returned nil")
	}
}

func TestVerifier_UpdateAndDelete(t *testing.T) {
	resetVerifierMap()
	dirPath, err := utils.CreatePlugin(licenseChecker)
	if err != nil {
		t.Fatalf("createPlugin() expected no error, actual %v", err)
	}
	defer os.RemoveAll(dirPath)

	var testVerifierSpec = getDefaultLicenseCheckerSpec(dirPath)

	// add a verifier
	if err := verifierAddOrReplace(testVerifierSpec, licenseChecker); err != nil {
		t.Fatalf("verifierAddOrReplace() expected no error, actual %v", err)
	}
	if len(controllers.NamespacedVerifiers.GetVerifiers(constants.EmptyNamespace)) != 1 {
		t.Fatalf("Verifier map expected size 1, actual %v", len(controllers.NamespacedVerifiers.GetVerifiers(constants.EmptyNamespace)))
	}

	// modify the verifier
	var parametersString = "{\"allowedLicenses\":[\"MIT\",\"GNU\"]}"
	testVerifierSpec = getLicenseCheckerFromParam(parametersString, dirPath)
	if err := verifierAddOrReplace(testVerifierSpec, licenseChecker); err != nil {
		t.Fatalf("verifierAddOrReplace() expected no error, actual %v", err)
	}

	// validate no verifier has been added
	if len(controllers.NamespacedVerifiers.GetVerifiers(constants.EmptyNamespace)) != 1 {
		t.Fatalf("Verifier map should be 1 after replacement, actual %v", len(controllers.NamespacedVerifiers.GetVerifiers(constants.EmptyNamespace)))
	}

	controllers.NamespacedVerifiers.DeleteVerifier(constants.EmptyNamespace, licenseChecker)

	if len(controllers.NamespacedVerifiers.GetVerifiers(constants.EmptyNamespace)) != 0 {
		t.Fatalf("Verifier map should be 0 after deletion, actual %v", len(controllers.NamespacedVerifiers.GetVerifiers(constants.EmptyNamespace)))
	}
}

func TestWriteVerifierStatus(t *testing.T) {
	logger := logrus.WithContext(context.Background())
	testCases := []struct {
		name                   string
		isSuccess              bool
		verifier               *configv1beta1.Verifier
		errString              string
		expectedErrString      string
		expectedBriefErrString string
		reconciler             client.StatusClient
	}{
		{
			name:       "success status",
			isSuccess:  true,
			errString:  "",
			verifier:   &configv1beta1.Verifier{},
			reconciler: &mockStatusClient{},
		},
		{
			name:                   "error status",
			isSuccess:              false,
			verifier:               &configv1beta1.Verifier{},
			errString:              "a long error string that exceeds the max length of 100 characters, a long error string that exceeds the max length of 100 characters",
			expectedErrString:      "UNKNOWN: a long error string that exceeds the max length of 100 characters, a long error string that exceeds the max length of 100 characters",
			expectedBriefErrString: "UNKNOWN: a long error string that exceeds the max length of 100 characters, a long error string t...",
			reconciler:             &mockStatusClient{},
		},
		{
			name:      "status update failed",
			isSuccess: true,
			verifier:  &configv1beta1.Verifier{},
			reconciler: &mockStatusClient{
				updateFailed: true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ratifyErr := re.ErrorCodeUnknown.WithDetail(tc.errString)
			writeVerifierStatus(context.Background(), tc.reconciler, tc.verifier, logger, tc.isSuccess, &ratifyErr)

			if tc.verifier.Status.IsSuccess != tc.isSuccess {
				t.Fatalf("Expected isSuccess to be %+v , actual %+v", tc.isSuccess, tc.verifier.Status.IsSuccess)
			}

			if tc.verifier.Status.Error != tc.expectedErrString {
				t.Fatalf("Expected Error to be %+v , actual %+v", tc.expectedErrString, tc.verifier.Status.Error)
			}

			if tc.verifier.Status.BriefError != tc.expectedBriefErrString {
				t.Fatalf("Expected BriefError to be %+v , actual %+v", tc.expectedBriefErrString, tc.verifier.Status.BriefError)
			}
		})
	}
}

func TestVerifierReconcile(t *testing.T) {
	dirPath, err := utils.CreatePlugin(sampleName)
	if err != nil {
		t.Fatalf("createPlugin() expected no error, actual %v", err)
	}
	defer os.RemoveAll(dirPath)

	tests := []struct {
		name                  string
		verifier              *configv1beta1.Verifier
		req                   *reconcile.Request
		expectedErr           bool
		expectedVerifierCount int
	}{
		{
			name: "nonexistent verifier",
			req: &reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "nonexistent"},
			},
			verifier: &configv1beta1.Verifier{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "",
					Name:      verifierName,
				},
			},
			expectedErr:           false,
			expectedVerifierCount: 0,
		},
		{
			name: "invalid parameters",
			verifier: &configv1beta1.Verifier{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "",
					Name:      verifierName,
				},
				Spec: configv1beta1.VerifierSpec{
					Parameters: runtime.RawExtension{
						Raw: []byte("test"),
					},
				},
			},
			expectedErr:           true,
			expectedVerifierCount: 0,
		},
		{
			name: "unsupported verifier",
			verifier: &configv1beta1.Verifier{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "",
					Name:      verifierName,
				},
				Spec: configv1beta1.VerifierSpec{
					Name:    "unsupported",
					Address: dirPath,
				},
			},
			expectedErr:           true,
			expectedVerifierCount: 0,
		},
		{
			name: "valid spec",
			verifier: &configv1beta1.Verifier{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "",
					Name:      verifierName,
				},
				Spec: configv1beta1.VerifierSpec{
					Name:    sampleName,
					Address: dirPath,
				},
			},
			expectedErr:           false,
			expectedVerifierCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetVerifierMap()
			scheme, _ := utils.CreateScheme()
			client := fake.NewClientBuilder().WithScheme(scheme)
			client.WithObjects(tt.verifier)
			r := &VerifierReconciler{
				Scheme: scheme,
				Client: client.Build(),
			}
			var req reconcile.Request
			if tt.req != nil {
				req = *tt.req
			} else {
				req = reconcile.Request{
					NamespacedName: utils.KeyFor(tt.verifier),
				}
			}

			_, err := r.Reconcile(context.Background(), req)
			if tt.expectedErr != (err != nil) {
				t.Fatalf("Reconcile() expected error %v, actual %v", tt.expectedErr, err)
			}
			if len(controllers.NamespacedVerifiers.GetVerifiers(constants.EmptyNamespace)) != tt.expectedVerifierCount {
				t.Fatalf("Verifier map expected size %v, actual %v", tt.expectedVerifierCount, len(controllers.NamespacedVerifiers.GetVerifiers(constants.EmptyNamespace)))
			}
		})
	}
}

func resetVerifierMap() {
	controllers.NamespacedVerifiers = verifiers.NewActiveVerifiers()
}

func getLicenseCheckerFromParam(parametersString, pluginPath string) configv1beta1.VerifierSpec {
	var allowedLicenses = []byte(parametersString)

	return configv1beta1.VerifierSpec{
		Name:          licenseChecker,
		ArtifactTypes: "application/vnd.ratify.spdx.v0",
		Address:       pluginPath,
		Parameters: runtime.RawExtension{
			Raw: allowedLicenses,
		},
	}
}

func getInvalidVerifierSpec() configv1beta1.VerifierSpec {
	return configv1beta1.VerifierSpec{
		Name:          "pluginnotfound",
		ArtifactTypes: "application/vnd.ratify.spdx.v0",
		Address:       "test/path",
	}
}

func getDefaultLicenseCheckerSpec(pluginPath string) configv1beta1.VerifierSpec {
	var parametersString = "{\"allowedLicenses\":[\"MIT\",\"Apache\"]}"
	return getLicenseCheckerFromParam(parametersString, pluginPath)
}
