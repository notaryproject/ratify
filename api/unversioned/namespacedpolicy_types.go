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

package unversioned

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// NamespacedPolicySpec defines the desired state of Policy
type NamespacedPolicySpec struct {
	// Important: Run "make" to regenerate code after modifying this file

	// Type of the policy
	Type string `json:"type,omitempty"`
	// Parameters for this policy
	Parameters runtime.RawExtension `json:"parameters,omitempty"`
}

// NamespacedPolicyStatus defines the observed state of Policy
type NamespacedPolicyStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Is successful while applying the policy.
	IsSuccess bool `json:"issuccess"`
	// Error message if NamespacedPolicy is not successfully applied.
	// +optional
	Error string `json:"error,omitempty"`
	// Truncated error message if the message is too long
	// +optional
	BriefError string `json:"brieferror,omitempty"`
}

// NamespacedPolicy is the Schema for the policies API
type NamespacedPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NamespacedPolicySpec   `json:"spec,omitempty"`
	Status NamespacedPolicyStatus `json:"status,omitempty"`
}

// NamespacedPolicyList contains a list of Policy
type NamespacedPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NamespacedPolicy `json:"items"`
}
