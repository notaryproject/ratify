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

import (
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	rc "github.com/notaryproject/ratify/v2/pkg/referrerstore/config"
)

type VerifierConfig map[string]interface{}

type PluginInputConfig struct {
	Config       VerifierConfig               `json:"config"`
	StoreConfig  rc.StoreConfig               `json:"storeConfig"`
	ReferencDesc ocispecs.ReferenceDescriptor `json:"referenceDesc"`
}

type VerifiersConfig struct {
	Version       string           `json:"version,omitempty"`
	PluginBinDirs []string         `json:"pluginBinDirs,omitempty"`
	Verifiers     []VerifierConfig `json:"plugins,omitempty"`
}
