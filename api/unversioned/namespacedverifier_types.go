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

// +kubebuilder:skip
package unversioned

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// NamespacedVerifierSpec defines the desired state of NamespacedVerifier
type NamespacedVerifierSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Name of the verifier. Deprecated
	Name string `json:"name"`

	// Type of the verifier. Optional
	Type string `json:"type,omitempty"`

	// Version of the verifier plugin. Optional
	Version string `json:"version,omitempty"`

	// The type of artifact this verifier handles
	ArtifactTypes string `json:"artifactTypes"`

	// URL/file path. Optional
	Address string `json:"address,omitempty"`

	// OCI Artifact source to download the plugin from. Optional
	Source *PluginSource `json:"source,omitempty"`

	// Parameters for this verifier
	Parameters runtime.RawExtension `json:"parameters,omitempty"`
}

// NamespacedVerifierStatus defines the observed state of NamespacedVerifier
type NamespacedVerifierStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Is successful in finding the plugin
	IsSuccess bool `json:"issuccess"`
	// Error message if operation was unsuccessful
	// +optional
	Error string `json:"error,omitempty"`
	// Truncated error message if the message is too long
	// +optional
	BriefError string `json:"brieferror,omitempty"`
}

// NamespacedVerifier is the Schema for the namespacedverifiers API
type NamespacedVerifier struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NamespacedVerifierSpec   `json:"spec,omitempty"`
	Status NamespacedVerifierStatus `json:"status,omitempty"`
}

// NamespacedVerifierList contains a list of NamespacedVerifier
type NamespacedVerifierList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NamespacedVerifier `json:"items"`
}
