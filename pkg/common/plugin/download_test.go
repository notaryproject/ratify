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

package plugin

import (
	"encoding/json"
	"testing"
)

func TestParsePluginSource_HandlesJSON(t *testing.T) {
	js := `{
	"name": "dynamic",
	"artifactTypes": "sbom/example",
	"nestedReferences": "application/vnd.cncf.notary.signature",
	"source": {
			"artifact": "wabbitnetworks.azurecr.io/test/sample-plugin:v1",
			"authProvider": {
				"name": "dockerConfig"
			}
	}
}`

	var verifierConfig map[string]interface{}
	err := json.Unmarshal([]byte(js), &verifierConfig)
	if err != nil {
		t.Fatalf("failed to unmarshal verifier config: %v", err)
	}

	source, err := ParsePluginSource(verifierConfig["source"])
	if err != nil {
		t.Fatalf("failed to parse plugin source: %v", err)
	}

	if source.Artifact != "wabbitnetworks.azurecr.io/test/sample-plugin:v1" {
		t.Fatalf("unexpected artifact: %s", source.Artifact)
	}

	if source.AuthProvider["name"] != "dockerConfig" {
		t.Fatalf("unexpected auth provider: %s", source.AuthProvider["name"])
	}
}

func TestParsePluginSource_HandlesCRD(t *testing.T) {
	verifierConfig := struct {
		Source *PluginSource
	}{
		Source: &PluginSource{
			Artifact: "wabbitnetworks.azurecr.io/test/sample-plugin:v1",
		},
	}

	source, err := ParsePluginSource(verifierConfig.Source)
	if err != nil {
		t.Fatalf("failed to parse plugin source: %v", err)
	}

	if source.Artifact != "wabbitnetworks.azurecr.io/test/sample-plugin:v1" {
		t.Fatalf("unexpected artifact: %s", source.Artifact)
	}
}
