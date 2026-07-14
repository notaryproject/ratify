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

	"github.com/notaryproject/ratify/v2/pkg/keymanagementprovider"
	"github.com/notaryproject/ratify/v2/pkg/keymanagementprovider/config"
	"github.com/notaryproject/ratify/v2/pkg/keymanagementprovider/mocks"
)

type TestKeyManagementProviderFactory struct{}

func (f TestKeyManagementProviderFactory) Create(_ string, _ config.KeyManagementProviderConfig, _ string) (keymanagementprovider.KeyManagementProvider, error) {
	return &mocks.TestKeyManagementProvider{}, nil
}

// TestRegister tests the Register function
func TestRegister(t *testing.T) {
	// test that the key management provider is registered
	Register("test-kmprovider", &TestKeyManagementProviderFactory{})
	if _, ok := builtInKeyManagementProviders["test-kmprovider"]; !ok {
		t.Fatalf("key management provider not registered")
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("Register should have panicked")
		}
	}()
	// test that Register panics on duplicate registration
	Register("test-kmprovider", &TestKeyManagementProviderFactory{})
}

// TestRegisterPanicsOnNil tests that Register panics on nil factory passed in
func TestRegisterPanicsOnNil(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("Register should have panicked")
		}
	}()
	// test that Register panics on nil factory
	Register("test-kmprovider", nil)
}

// TestCreateKeyManagementProvidersFromConfig_BuiltInKeyManagementProviders_ReturnsExpected checks the correct registered key management provider is invoked based on config
func TestCreateKeyManagementProvidersFromConfig_BuiltInKeyManagementProvider_ReturnsExpected(t *testing.T) {
	builtInKeyManagementProviders = map[string]KeyManagementProviderFactory{
		"test-kmprovider": TestKeyManagementProviderFactory{},
	}

	config := config.KeyManagementProviderConfig{
		"type": "test-kmprovider",
	}

	_, err := CreateKeyManagementProviderFromConfig(config, "", "")
	if err != nil {
		t.Fatalf("create key management provider should not have failed: %v", err)
	}
}

// TestCreateKeyManagementProvidersFromConfig_NonexistentKeyManagementProviders_ReturnsExpected checks the key management provider creation fails if key management provider specified does not exist
func TestCreateKeyManagementProvidersFromConfig_NonexistentKeyManagementProviders_ReturnsExpected(t *testing.T) {
	builtInKeyManagementProviders = map[string]KeyManagementProviderFactory{
		"testkeymanagementprovider": TestKeyManagementProviderFactory{},
	}

	config := config.KeyManagementProviderConfig{
		"type": "test-nonexistent",
	}

	_, err := CreateKeyManagementProviderFromConfig(config, "", "")
	if err == nil {
		t.Fatal("create key management provider should have failed")
	}
}

// TestCreateKeyManagementProvidersFromConfig_MissingType_ReturnsExpected checks the key management provider creation fails if type field is missing in config
func TestCreateKeyManagementProvidersFromConfig_MissingType_ReturnsExpected(t *testing.T) {
	builtInKeyManagementProviders = map[string]KeyManagementProviderFactory{
		"testkeymanagementprovider": TestKeyManagementProviderFactory{},
	}

	config := config.KeyManagementProviderConfig{
		"nonexistent": "test-nonexistent",
	}

	_, err := CreateKeyManagementProviderFromConfig(config, "", "")
	if err == nil {
		t.Fatal("create key management provider should have failed")
	}
}

// TestCreateKeyManagementProvidersFromConfig_EmptyType_ReturnsExpected checks the key management provider creation fails if type field is empty in config
func TestCreateKeyManagementProvidersFromConfig_EmptyType_ReturnsExpected(t *testing.T) {
	builtInKeyManagementProviders = map[string]KeyManagementProviderFactory{
		"testkeymanagementprovider": TestKeyManagementProviderFactory{},
	}

	config := config.KeyManagementProviderConfig{}

	_, err := CreateKeyManagementProviderFromConfig(config, "", "")
	if err == nil {
		t.Fatal("create key management provider should have failed")
	}
}
