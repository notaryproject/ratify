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
	re "github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/pkg/controllers"
	"github.com/notaryproject/ratify/v2/pkg/customresources/policies"
	_ "github.com/notaryproject/ratify/v2/pkg/policyprovider/configpolicy"
	_ "github.com/notaryproject/ratify/v2/pkg/policyprovider/regopolicy"
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
	policyName1   = "policy1"
	policyName2   = "policy2"
	testNamespace = "testNamespace"
)

func TestPolicyAddOrReplace(t *testing.T) {
	testCases := []struct {
		name       string
		spec       configv1beta1.NamespacedPolicySpec
		policyName string
		expectErr  bool
	}{
		{
			name: "invalid spec",
			spec: configv1beta1.NamespacedPolicySpec{
				Type: policyName1,
			},
			expectErr: true,
		},
		{
			name: "valid spec",
			spec: configv1beta1.NamespacedPolicySpec{
				Parameters: runtime.RawExtension{
					Raw: []byte("{\"name\": \"configpolicy\"}"),
				},
				Type: "configpolicy",
			},
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := policyAddOrReplace(tc.spec, testNamespace)

			if tc.expectErr != (err != nil) {
				t.Fatalf("Expected error to be %t, got %t", tc.expectErr, err != nil)
			}
		})
	}
}

func TestPolicyAddedTwice(t *testing.T) {
	resetPolicyMap()
	spec1 := configv1beta1.NamespacedPolicySpec{
		Parameters: runtime.RawExtension{
			Raw: []byte("{\"name\": \"configpolicy\"}"),
		},
		Type: "configpolicy",
	}
	spec2 := configv1beta1.NamespacedPolicySpec{
		Type: "regopolicy",
		Parameters: runtime.RawExtension{
			Raw: []byte("{\"name\": \"regopolicy\", \"policy\": \"package ratify.policy\"}"),
		},
	}
	if err := policyAddOrReplace(spec1, testNamespace); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if err := policyAddOrReplace(spec2, testNamespace); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	policyType := controllers.NamespacedPolicies.GetPolicy(testNamespace).GetPolicyType(context.Background())
	if policyType != "regopolicy" {
		t.Fatalf("expected policy type to be regopolicy, got %s", policyType)
	}
}

func TestWritePolicyStatus(t *testing.T) {
	logger := logrus.WithContext(context.Background())
	testCases := []struct {
		name       string
		isSuccess  bool
		policy     *configv1beta1.NamespacedPolicy
		errString  string
		reconciler client.StatusClient
	}{
		{
			name:       "success status",
			isSuccess:  true,
			policy:     &configv1beta1.NamespacedPolicy{},
			reconciler: &test.MockStatusClient{},
		},
		{
			name:       "error status",
			isSuccess:  false,
			policy:     &configv1beta1.NamespacedPolicy{},
			errString:  "a long error string that exceeds the max length of 30 characters",
			reconciler: &test.MockStatusClient{},
		},
		{
			name:      "status update failed",
			isSuccess: true,
			policy:    &configv1beta1.NamespacedPolicy{},
			reconciler: &test.MockStatusClient{
				UpdateFailed: true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(_ *testing.T) {
			err := re.ErrorCodeUnknown.WithDetail(tc.errString)
			writePolicyStatus(context.Background(), tc.reconciler, tc.policy, logger, tc.isSuccess, &err)
		})
	}
}

func TestPolicyReconcile(t *testing.T) {
	tests := []struct {
		name           string
		policy         *configv1beta1.NamespacedPolicy
		req            *reconcile.Request
		expectedErr    bool
		expectedPolicy bool
	}{
		{
			name: "nonexistent policy",
			req: &reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "nonexistent"},
			},
			policy: &configv1beta1.NamespacedPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testNamespace,
					Name:      policyName1,
				},
			},
			expectedErr:    false,
			expectedPolicy: false,
		},
		{
			name: "no policy parameters provided",
			policy: &configv1beta1.NamespacedPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testNamespace,
					Name:      "ratify-policy",
				},
				Spec: configv1beta1.NamespacedPolicySpec{
					Type: "regopolicy",
				},
			},
			expectedErr:    true,
			expectedPolicy: false,
		},
		{
			name: "wrong policy name",
			policy: &configv1beta1.NamespacedPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testNamespace,
					Name:      "ratify-policy2",
				},
				Spec: configv1beta1.NamespacedPolicySpec{
					Type: "regopolicy",
				},
			},
			expectedErr:    false,
			expectedPolicy: false,
		},
		{
			name: "invalid params",
			policy: &configv1beta1.NamespacedPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testNamespace,
					Name:      "ratify-policy",
				},
				Spec: configv1beta1.NamespacedPolicySpec{
					Type: "regopolicy",
					Parameters: runtime.RawExtension{
						Raw: []byte("test"),
					},
				},
			},
			expectedErr:    true,
			expectedPolicy: false,
		},
		{
			name: "valid params",
			policy: &configv1beta1.NamespacedPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testNamespace,
					Name:      "ratify-policy",
				},
				Spec: configv1beta1.NamespacedPolicySpec{
					Type: "configpolicy",
					Parameters: runtime.RawExtension{
						Raw: []byte("{\"passthroughEnabled:\": false}"),
					},
				},
			},
			expectedErr:    false,
			expectedPolicy: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetPolicyMap()
			scheme, err := test.CreateScheme()
			if err != nil {
				t.Fatalf("CreateScheme() expected no error, actual %v", err)
			}
			client := fake.NewClientBuilder().WithScheme(scheme)
			client.WithObjects(tt.policy)
			r := &PolicyReconciler{
				Scheme: scheme,
				Client: client.Build(),
			}
			var req reconcile.Request
			if tt.req != nil {
				req = *tt.req
			} else {
				req = reconcile.Request{
					NamespacedName: test.KeyFor(tt.policy),
				}
			}
			_, err = r.Reconcile(context.Background(), req)
			if tt.expectedErr != (err != nil) {
				t.Fatalf("Reconcile() expected error to be %t, actual %t", tt.expectedErr, err != nil)
			}
			test := controllers.NamespacedPolicies

			policy := test.GetPolicy(testNamespace)
			if (policy != nil) != tt.expectedPolicy {
				t.Fatalf("Expected policy to be %t, got %t", tt.expectedPolicy, policy != nil)
			}
		})
	}
}

func resetPolicyMap() {
	controllers.NamespacedPolicies = policies.NewActivePolicies()
}
