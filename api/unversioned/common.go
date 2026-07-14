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

import runtime "k8s.io/apimachinery/pkg/runtime"

// PluginSource defines the fields needed to download a plugin from an OCI Artifact source
type PluginSource struct {
	// Important: Run "make" to regenerate code after modifying this file

	// OCI Artifact source to download the plugin from
	Artifact string `json:"artifact,omitempty"`

	// +kubebuilder:pruning:PreserveUnknownFields
	// AuthProvider to use to authenticate to the OCI Artifact source, optional
	AuthProvider runtime.RawExtension `json:"authProvider,omitempty"`
}
