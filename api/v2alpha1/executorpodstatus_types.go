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

// PodStatusEntry captures the health a single Ratify pod (replica) reports for
// an Executor resource. It is the unit that is written by each pod into its own
// ExecutorPodStatus object and later aggregated into Executor.status.byPod.
type PodStatusEntry struct {
	// ID is the name of the pod that produced this status entry. Required.
	ID string `json:"id"`

	// ObservedGeneration is the metadata.generation of the Executor that this
	// entry was produced for.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Succeeded indicates whether the reporting pod successfully built the
	// executor from the Executor spec. Required.
	Succeeded bool `json:"succeeded"`

	// Error is the error message if the reporting pod failed to build the
	// executor.
	// +optional
	Error string `json:"error,omitempty"`

	// BriefError is a truncated error message when Error is too long to be
	// displayed conveniently.
	// +optional
	BriefError string `json:"briefError,omitempty"`

	// LastTransitionTime is the time the reporting pod last updated this entry.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// ExecutorPodStatus is the per-pod status of an Executor. Each Ratify replica
// owns exactly one ExecutorPodStatus object per Executor (the object name embeds
// the pod identity), so no two pods ever write the same object and there are no
// write conflicts. The object lives in the pod's own namespace and carries an
// owner reference to the pod, so it is garbage-collected automatically when the
// pod is deleted. (It is namespaced rather than cluster-scoped because a
// cluster-scoped object cannot be owned by a namespaced pod.)
type ExecutorPodStatus struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Status PodStatusEntry `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ExecutorPodStatusList contains a list of ExecutorPodStatus.
type ExecutorPodStatusList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ExecutorPodStatus `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ExecutorPodStatus{}, &ExecutorPodStatusList{})
}
