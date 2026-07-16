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

package factory

import (
	"context"
	"os"
	"testing"

	"github.com/notaryproject/ratify/v2/internal/constants"
	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/featureflag"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"

	"github.com/notaryproject/ratify/v2/pkg/utils"
	"github.com/notaryproject/ratify/v2/pkg/verifier"
	"github.com/notaryproject/ratify/v2/pkg/verifier/config"
	"github.com/notaryproject/ratify/v2/pkg/verifier/plugin"
)

type TestVerifier struct {
	verifierDirectory string
}
type TestVerifierFactory struct{}

func (s *TestVerifier) Name() string {
	return "test-verifier-0"
}

func (s *TestVerifier) Type() string {
	return "test-verifier"
}

func (s *TestVerifier) CanVerify(_ context.Context, _ ocispecs.ReferenceDescriptor) bool {
	return true
}

func (s *TestVerifier) Verify(_ context.Context,
	_ common.Reference,
	_ ocispecs.ReferenceDescriptor,
	_ referrerstore.ReferrerStore) (verifier.VerifierResult, error) {
	return verifier.VerifierResult{IsSuccess: false}, nil
}

func (s *TestVerifier) GetNestedReferences() []string {
	return []string{}
}

func (f *TestVerifierFactory) Create(_ string, _ config.VerifierConfig, pluginDirectory string, _ string) (verifier.ReferenceVerifier, error) {
	return &TestVerifier{verifierDirectory: pluginDirectory}, nil
}

func TestCreateVerifiersFromConfig_BuiltInVerifiers_ReturnsExpected(t *testing.T) {
	builtInVerifiers = map[string]VerifierFactory{
		"test-verifier": &TestVerifierFactory{},
	}

	verifierConfig := map[string]interface{}{
		"name": "test-verifier-0",
		"type": "test-verifier",
	}
	verifiersConfig := config.VerifiersConfig{
		Verifiers: []config.VerifierConfig{verifierConfig},
	}

	verifiers, err := CreateVerifiersFromConfig(verifiersConfig, "test/dir", constants.EmptyNamespace)

	if err != nil {
		t.Fatalf("create verifiers failed with err %v", err)
	}

	if len(verifiers) != 1 {
		t.Fatalf("expected to have %d verifiers, actual count %d", 1, len(verifiers))
	}

	if nameResult := verifiers[0].Name(); nameResult != "test-verifier-0" {
		t.Fatalf("expected to create test-verifier-0 for test case but got %v", nameResult)
	}

	if _, ok := verifiers[0].(*plugin.VerifierPlugin); ok {
		t.Fatalf("type assertion failed expected a built in verifier")
	}

	if verifierTest, ok := verifiers[0].(*TestVerifier); !ok {
		t.Fatalf("type assertion failed expected a test verifier")
	} else {
		if verifierTest.verifierDirectory != "test/dir" {
			t.Fatalf("expected verifier directory to be empty")
		}
	}
}

func TestCreateVerifiersFromConfig_InvalidConfig_ReturnsErr(t *testing.T) {
	verifierConfig := map[string]interface{}{
		"name": "test-verifier-0",
	}
	verifiersConfig := config.VerifiersConfig{
		Verifiers: []config.VerifierConfig{verifierConfig},
	}

	_, err := CreateVerifiersFromConfig(verifiersConfig, "test/dir", constants.EmptyNamespace)

	if err == nil {
		t.Fatalf("expected to have an error")
	}
}

func TestCreateVerifiersFromConfig_PluginVerifiers_ReturnsExpected(t *testing.T) {
	dirPath, err := utils.CreatePlugin("sample")
	if err != nil {
		t.Fatalf("createPlugin() expected no error, actual %v", err)
	}
	defer os.RemoveAll(dirPath)

	verifierConfig := map[string]interface{}{
		"name":    "plugin-verifier-0",
		"type":    "sample",
		"version": "1.0.0",
	}
	verifiersConfig := config.VerifiersConfig{
		Verifiers: []config.VerifierConfig{verifierConfig},
	}

	verifiers, err := CreateVerifiersFromConfig(verifiersConfig, dirPath, "")

	if err != nil {
		t.Fatalf("create verifiers failed with err %v", err)
	}

	if len(verifiers) != 1 {
		t.Fatalf("expected to have %d verifiers, actual count %d", 1, len(verifiers))
	}

	if verifiers[0].Name() != "plugin-verifier-0" {
		t.Fatalf("expected to create plugin-verifier-0")
	}

	if _, ok := verifiers[0].(*plugin.VerifierPlugin); !ok {
		t.Fatalf("type assertion failed expected a plugin in verifier")
	}
}

func TestCreateVerifiersFromConfig_EmptyVerifiers_ReturnsErr(t *testing.T) {
	verifiersConfig := config.VerifiersConfig{}

	_, err := CreateVerifiersFromConfig(verifiersConfig, "test/dir", "")

	if err == nil {
		t.Fatalf("expected to have an error")
	}
}

func TestCreateVerifierFromConfig(t *testing.T) {
	tests := []struct {
		name                 string
		verifierConfig       config.VerifierConfig
		configVersion        string
		pluginBinDir         []string
		namespace            string
		dynamicPluginEnabled bool
		expectedErr          bool
	}{
		{
			name:           "missing name",
			verifierConfig: config.VerifierConfig{},
			expectedErr:    true,
		},
		{
			name: "verifier type contains path separator",
			verifierConfig: config.VerifierConfig{
				"name": "test/verifier",
			},
			expectedErr: true,
		},
		{
			name: "external verifier plugin not found",
			verifierConfig: config.VerifierConfig{
				"name": "not-found",
			},
			pluginBinDir: []string{"test/path"},
			expectedErr:  true,
		},
		{
			name: "parse plugin source failed",
			verifierConfig: config.VerifierConfig{
				"name":   "test-verifier",
				"source": "invalid",
			},
			dynamicPluginEnabled: true,
			expectedErr:          true,
		},
		{
			name: "download plugin failed",
			verifierConfig: config.VerifierConfig{
				"name": "test-verifier",
				"source": map[string]interface{}{
					"artifact": "invalid",
				},
			},
			pluginBinDir:         []string{"test/path"},
			dynamicPluginEnabled: true,
			expectedErr:          true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if tt.dynamicPluginEnabled {
				dynamicVal := featureflag.DynamicPlugins.Enabled
				t.Cleanup(func() { featureflag.DynamicPlugins.Enabled = dynamicVal })
				featureflag.DynamicPlugins.Enabled = true
			}

			_, err := CreateVerifierFromConfig(tt.verifierConfig, tt.configVersion, tt.pluginBinDir, tt.namespace)
			if tt.expectedErr != (err != nil) {
				t.Fatalf("expected error %v, actual %v", tt.expectedErr, err)
			}
		})
	}
}
