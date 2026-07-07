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

package v2alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestExecutorDeepCopy(t *testing.T) {
	executor := &Executor{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Executor",
			APIVersion: GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-executor",
			Namespace: "test-namespace",
			Labels: map[string]string{
				"app": "ratify",
			},
		},
		Spec: ExecutorSpec{
			Scopes: []string{"namespace-a", "namespace-b"},
			Verifiers: []*VerifierOptions{
				{
					Name:       "notation",
					Type:       "notation",
					Parameters: runtime.RawExtension{Raw: []byte(`{"trustPolicyDoc":"policy"}`)},
				},
				nil,
			},
			Stores: []*StoreOptions{
				{
					Type:       "oras",
					Parameters: runtime.RawExtension{Raw: []byte(`{"cacheEnabled":true}`)},
				},
				nil,
			},
			PolicyEnforcer: &PolicyEnforcerOptions{
				Type:       "threshold",
				Parameters: runtime.RawExtension{Raw: []byte(`{"threshold":1}`)},
			},
			Concurrency: 4,
		},
		Status: ExecutorStatus{
			Succeeded:  true,
			Error:      "full error",
			BriefError: "brief error",
		},
	}

	copied := executor.DeepCopy()
	if copied == executor {
		t.Fatal("expected a distinct Executor copy")
	}
	if copied.Name != executor.Name || copied.Namespace != executor.Namespace {
		t.Fatalf("expected metadata to be copied, got %s/%s", copied.Namespace, copied.Name)
	}
	if copied.Spec.Verifiers[0] == executor.Spec.Verifiers[0] {
		t.Fatal("expected verifier options to be deep copied")
	}
	if copied.Spec.Stores[0] == executor.Spec.Stores[0] {
		t.Fatal("expected store options to be deep copied")
	}
	if copied.Spec.PolicyEnforcer == executor.Spec.PolicyEnforcer {
		t.Fatal("expected policy enforcer options to be deep copied")
	}
	if copied.Spec.Verifiers[1] != nil {
		t.Fatal("expected nil verifier entry to remain nil")
	}
	if copied.Spec.Stores[1] != nil {
		t.Fatal("expected nil store entry to remain nil")
	}

	executor.Labels["app"] = "mutated"
	executor.Spec.Scopes[0] = "mutated"
	executor.Spec.Verifiers[0].Parameters.Raw[0] = '['
	executor.Spec.Stores[0].Parameters.Raw[0] = '['
	executor.Spec.PolicyEnforcer.Parameters.Raw[0] = '['

	if copied.Labels["app"] != "ratify" {
		t.Errorf("expected labels to be isolated, got %q", copied.Labels["app"])
	}
	if copied.Spec.Scopes[0] != "namespace-a" {
		t.Errorf("expected scopes to be isolated, got %q", copied.Spec.Scopes[0])
	}
	if string(copied.Spec.Verifiers[0].Parameters.Raw) != `{"trustPolicyDoc":"policy"}` {
		t.Errorf("expected verifier parameters to be isolated, got %s", copied.Spec.Verifiers[0].Parameters.Raw)
	}
	if string(copied.Spec.Stores[0].Parameters.Raw) != `{"cacheEnabled":true}` {
		t.Errorf("expected store parameters to be isolated, got %s", copied.Spec.Stores[0].Parameters.Raw)
	}
	if string(copied.Spec.PolicyEnforcer.Parameters.Raw) != `{"threshold":1}` {
		t.Errorf("expected policy enforcer parameters to be isolated, got %s", copied.Spec.PolicyEnforcer.Parameters.Raw)
	}

	if obj := executor.DeepCopyObject(); obj == nil {
		t.Fatal("expected non-nil runtime object copy")
	}
}

func TestExecutorListDeepCopy(t *testing.T) {
	list := &ExecutorList{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ExecutorList",
			APIVersion: GroupVersion.String(),
		},
		ListMeta: metav1.ListMeta{
			ResourceVersion: "123",
		},
		Items: []Executor{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "executor-a"},
				Spec: ExecutorSpec{
					Scopes: []string{"namespace-a"},
					Verifiers: []*VerifierOptions{
						{Name: "notation", Type: "notation"},
					},
				},
			},
		},
	}

	copied := list.DeepCopy()
	if copied == list {
		t.Fatal("expected a distinct ExecutorList copy")
	}
	if copied.Items[0].Spec.Verifiers[0] == list.Items[0].Spec.Verifiers[0] {
		t.Fatal("expected nested Executor items to be deep copied")
	}

	list.Items[0].Spec.Verifiers[0].Name = "mutated"
	if copied.Items[0].Spec.Verifiers[0].Name != "notation" {
		t.Errorf("expected copied list item to be isolated, got %q", copied.Items[0].Spec.Verifiers[0].Name)
	}

	if obj := list.DeepCopyObject(); obj == nil {
		t.Fatal("expected non-nil runtime object copy")
	}
}

func TestDeepCopyNilReceivers(t *testing.T) {
	var executor *Executor
	if executor.DeepCopy() != nil {
		t.Fatal("expected nil Executor deepcopy")
	}
	if executor.DeepCopyObject() != nil {
		t.Fatal("expected nil Executor runtime object deepcopy")
	}

	var executorList *ExecutorList
	if executorList.DeepCopy() != nil {
		t.Fatal("expected nil ExecutorList deepcopy")
	}
	if executorList.DeepCopyObject() != nil {
		t.Fatal("expected nil ExecutorList runtime object deepcopy")
	}

	var spec *ExecutorSpec
	if spec.DeepCopy() != nil {
		t.Fatal("expected nil ExecutorSpec deepcopy")
	}

	var status *ExecutorStatus
	if status.DeepCopy() != nil {
		t.Fatal("expected nil ExecutorStatus deepcopy")
	}

	var policyEnforcer *PolicyEnforcerOptions
	if policyEnforcer.DeepCopy() != nil {
		t.Fatal("expected nil PolicyEnforcerOptions deepcopy")
	}

	var store *StoreOptions
	if store.DeepCopy() != nil {
		t.Fatal("expected nil StoreOptions deepcopy")
	}

	var verifier *VerifierOptions
	if verifier.DeepCopy() != nil {
		t.Fatal("expected nil VerifierOptions deepcopy")
	}
}
