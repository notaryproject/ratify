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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

type VerifierOptions struct {
	// Name is the unique identifier of a verifier instance. Required.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Type represents a specific implementation of a verifier. Required.
	// Note: there could be multiple verifiers of the same type with different
	//       names.
	// +kubebuilder:validation:MinLength=1
	Type string `json:"type"`

	// Parameters is additional parameters of the verifier. Optional.
	Parameters runtime.RawExtension `json:"parameters,omitempty"`
}

type StoreOptions struct {
	// Type represents a specific implementation of a store. Required.
	// +kubebuilder:validation:MinLength=1
	Type string `json:"type"`

	// Parameters is additional parameters for the store. Optional.
	Parameters runtime.RawExtension `json:"parameters,omitempty"`
}

type PolicyEnforcerOptions struct {
	// Type represents a specific implementation of a policy enforcer. Required.
	// +kubebuilder:validation:MinLength=1
	Type string `json:"type"`

	// Parameters is additional parameters for the policy enforcer. Optional.
	Parameters runtime.RawExtension `json:"parameters,omitempty"`
}

// ExecutorSpec defines the desired state of Executor.
type ExecutorSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Scopes defines the scopes for which this executor is responsible. At
	// least one non-empty scope must be provided. Required.
	// +kubebuilder:validation:MinItems=1
	Scopes []string `json:"scopes"`

	// Verifiers contains the configuration options for the verifiers. At least
	// one verifier must be provided. Required.
	// +kubebuilder:validation:MinItems=1
	Verifiers []*VerifierOptions `json:"verifiers"`

	// Stores contains the configuration options for the stores. At least one
	// store must be provided. Required.
	// +kubebuilder:validation:MinItems=1
	Stores []*StoreOptions `json:"stores"`

	// PolicyEnforcer contains the configuration options for the policy
	// enforcer. Optional.
	PolicyEnforcer *PolicyEnforcerOptions `json:"policyEnforcer,omitempty"`

	// Concurrency limits the maximum number of concurrent execution per
	// validation request. If less than or equal to 0, a default (currently 3)
	// will be used. Optional.
	Concurrency int `json:"concurrency,omitempty"`
}

// ExecutorStatus defines the observed state of Executor.
type ExecutorStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Succeeded indicates whether the executor has successfully started and is
	// ready to process requests. Required.
	Succeeded bool `json:"succeeded"`

	// Error is the error message if the executor failed to start.
	// +optional
	Error string `json:"error,omitempty"`

	// Truncated error message if the message is too long.
	// +optional
	BriefError string `json:"briefError,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope="Cluster"
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Succeeded",type=boolean,JSONPath=`.status.succeeded`
// +kubebuilder:printcolumn:name="Error",type=string,JSONPath=`.status.briefError`
// Executor is the Schema for the executors API.
type Executor struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ExecutorSpec   `json:"spec,omitempty"`
	Status ExecutorStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ExecutorList contains a list of Executor.
type ExecutorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Executor `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Executor{}, &ExecutorList{})
}
