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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// VerifierSpec defines the desired state of Verifier
type VerifierSpec struct {
	// Important: Run "make" to regenerate code after modifying this file

	// Name of the verifier
	Name string `json:"name,omitempty"`

	// The type of artifact this verifier handles
	ArtifactTypes string `json:"artifactTypes,omitempty"`

	// # Optional. URL/file path
	Address string `json:"address,omitempty"`

	// OCI Artifact source to download the plugin from, optional
	Source *PluginSource `json:"source,omitempty"`

	// +kubebuilder:pruning:PreserveUnknownFields
	// Parameters for this verifier
	Parameters runtime.RawExtension `json:"parameters,omitempty"`
}

// VerifierStatus defines the observed state of Verifier
type VerifierStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope="Cluster"
// +kubebuilder:deprecatedversion:warning="v1alpha1 of the Verifier API has been deprecated. Please migrate to v1beta1."

// Verifier is the Schema for the verifiers API
type Verifier struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VerifierSpec   `json:"spec,omitempty"`
	Status VerifierStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// VerifierList contains a list of Verifier
type VerifierList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Verifier `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(GroupVersion, &Verifier{}, &VerifierList{})
		return nil
	})
}
