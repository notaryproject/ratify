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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

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

	// +kubebuilder:pruning:PreserveUnknownFields
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

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope="Namespaced"
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="IsSuccess",type=boolean,JSONPath=`.status.issuccess`
// +kubebuilder:printcolumn:name="Error",type=string,JSONPath=`.status.brieferror`
// NamespacedVerifier is the Schema for the namespacedverifiers API
type NamespacedVerifier struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NamespacedVerifierSpec   `json:"spec,omitempty"`
	Status NamespacedVerifierStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// NamespacedVerifierList contains a list of NamespacedVerifier
type NamespacedVerifierList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NamespacedVerifier `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NamespacedVerifier{}, &NamespacedVerifierList{})
}
