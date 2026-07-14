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

// KeyManagementProviderSpec defines the desired state of KeyManagementProvider
type KeyManagementProviderSpec struct {
	// Important: Run "make" to regenerate code after modifying this file

	// Name of the key management provider
	Type string `json:"type,omitempty"`

	// Refresh interval for fetching the certificate/key files from the provider. Only for providers that are refreshable. The value is in the format of "1h30m" where "h" means hour and "m" means minute. Valid time units are units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
	// +kubebuilder:default=""
	RefreshInterval string `json:"refreshInterval,omitempty"`

	// +kubebuilder:pruning:PreserveUnknownFields
	// Parameters of the key management provider
	Parameters runtime.RawExtension `json:"parameters,omitempty"`
}

// KeyManagementProviderStatus defines the observed state of KeyManagementProvider
type KeyManagementProviderStatus struct {
	// Important: Run "make manifests" to regenerate code after modifying this file

	// Is successful in loading certificate/key files
	IsSuccess bool `json:"issuccess"`
	// Error message if operation was unsuccessful
	// +optional
	Error string `json:"error,omitempty"`
	// Truncated error message if the message is too long
	// +optional
	BriefError string `json:"brieferror,omitempty"`
	// The time stamp of last successful certificate/key fetch operation. If operation failed, last fetched time shows the time of error
	// +optional
	LastFetchedTime *metav1.Time `json:"lastfetchedtime,omitempty"`
	// +kubebuilder:pruning:PreserveUnknownFields
	// provider specific properties of the each individual certificate/key
	// +optional
	Properties runtime.RawExtension `json:"properties,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope="Cluster"
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="IsSuccess",type=boolean,JSONPath=`.status.issuccess`
// +kubebuilder:printcolumn:name="Error",type=string,JSONPath=`.status.brieferror`
// +kubebuilder:printcolumn:name="LastFetchedTime",type=date,JSONPath=`.status.lastfetchedtime`
// KeyManagementProvider is the Schema for the keymanagementproviders API
type KeyManagementProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KeyManagementProviderSpec   `json:"spec,omitempty"`
	Status KeyManagementProviderStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// KeyManagementProviderList contains a list of KeyManagementProvider
type KeyManagementProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeyManagementProvider `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeyManagementProvider{}, &KeyManagementProviderList{})
}
