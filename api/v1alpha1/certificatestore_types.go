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

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// CertificateStoreSpec defines the desired state of CertificateStore
type CertificateStoreSpec struct {
	// Important: Run "make" to regenerate code after modifying this file

	// Name of the certificate store provider
	Provider string `json:"provider,omitempty"`

	// +kubebuilder:pruning:PreserveUnknownFields
	// Parameters of the certificate store
	Parameters runtime.RawExtension `json:"parameters,omitempty"`
}

// CertificateStoreStatus defines the observed state of CertificateStore
type CertificateStoreStatus struct {
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:deprecatedversion:warning="v1alpha1 of the CertificateStore API has been deprecated. Please migrate to v1beta1."

// CertificateStore is the Schema for the certificatestores API
type CertificateStore struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertificateStoreSpec   `json:"spec,omitempty"`
	Status CertificateStoreStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// CertificateStoreList contains a list of CertificateStore
type CertificateStoreList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CertificateStore `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(GroupVersion, &CertificateStore{}, &CertificateStoreList{})
		return nil
	})
}
