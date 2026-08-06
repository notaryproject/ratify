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
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope="Namespaced"
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Succeeded",type=boolean,JSONPath=`.status.succeeded`
// +kubebuilder:printcolumn:name="Error",type=string,JSONPath=`.status.briefError`

// NamespacedExecutor is the Schema for the namespaced executors API. It enables
// multi-tenancy by allowing each namespace to define its own executor
// configuration. A NamespacedExecutor only applies to validation requests for
// workloads deployed in the same namespace. When no NamespacedExecutor matches
// a request's namespace, Ratify falls back to the cluster-scoped Executor.
//
// Security note: because a NamespacedExecutor overrides the cluster-scoped
// Executor for its namespace, it can weaken image verification there. Write
// access to NamespacedExecutor resources should be tightly restricted to
// trusted namespace admins.
type NamespacedExecutor struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ExecutorSpec   `json:"spec,omitempty"`
	Status ExecutorStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NamespacedExecutorList contains a list of NamespacedExecutor.
type NamespacedExecutorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NamespacedExecutor `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NamespacedExecutor{}, &NamespacedExecutorList{})
}
