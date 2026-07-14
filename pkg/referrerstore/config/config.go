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

package config

// StorePluginConfig represents the configuration of a store plugin
type StorePluginConfig map[string]interface{}

// StoresConfig represents configuration of multiple store plugins
type StoresConfig struct {
	Version       string              `json:"version,omitempty"`
	PluginBinDirs []string            `json:"pluginBinDirs,omitempty"`
	Stores        []StorePluginConfig `json:"plugins,omitempty"`
}

// StoreConfig represents the configuration of a store plugin that is passed to a verifier
type StoreConfig struct {
	Version       string            `json:"version"`
	PluginBinDirs []string          `json:"pluginBinDirs"`
	Store         StorePluginConfig `json:"store"`
}
