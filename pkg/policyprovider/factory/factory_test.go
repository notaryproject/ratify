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
	"testing"

	"github.com/notaryproject/ratify/v2/pkg/policyprovider"
	"github.com/notaryproject/ratify/v2/pkg/policyprovider/config"
	"github.com/notaryproject/ratify/v2/pkg/policyprovider/mocks"
)

type TestPolicyProviderFactory struct{}

func (f *TestPolicyProviderFactory) Create(_ config.PolicyPluginConfig) (policyprovider.PolicyProvider, error) {
	return &mocks.TestPolicyProvider{}, nil
}

// Checks the correct registered policy provider is invoked based on config
func TestCreatePolicyProvidersFromConfig_BuiltInPolicyProviders_ReturnsExpected(t *testing.T) {
	builtInPolicyProviders = map[string]PolicyFactory{
		"testpolicyprovider": &TestPolicyProviderFactory{},
	}

	configPolicyConfig := map[string]interface{}{
		"name": "test-policyprovider",
	}
	policyProviderConfig := config.PoliciesConfig{
		Version:      "1.0.0",
		PolicyPlugin: configPolicyConfig,
	}

	_, err := CreatePolicyProviderFromConfig(policyProviderConfig)
	if err != nil {
		t.Fatalf("create policy provider failed with err %v", err)
	}
}

// Checks the auth provider creation fails if auth provider specified does not exist
func TestCreatePolicyProvidersFromConfig_NonexistentPolicyProviders_ReturnsExpected(t *testing.T) {
	builtInPolicyProviders = map[string]PolicyFactory{
		"test-policyprovider": &TestPolicyProviderFactory{},
	}

	configPolicyConfig := map[string]interface{}{
		"name": "test-nonexistent",
	}
	policyProviderConfig := config.PoliciesConfig{
		Version:      "1.0.0",
		PolicyPlugin: configPolicyConfig,
	}

	_, err := CreatePolicyProviderFromConfig(policyProviderConfig)
	if err == nil {
		t.Fatalf("create policy provider should have failed for non existent provider")
	}
}
