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

package utils

import (
	"os"
	"testing"

	configv1beta1 "github.com/notaryproject/ratify/v2/api/v1beta1"
	rc "github.com/notaryproject/ratify/v2/pkg/referrerstore/config"
	test "github.com/notaryproject/ratify/v2/pkg/utils"
	"github.com/notaryproject/ratify/v2/pkg/verifier/types"
)

const (
	storeName     = "storeName"
	testNamespace = "testNamespace"
)

func TestUpsertStoreMap(t *testing.T) {
	dirPath, err := test.CreatePlugin(storeName)
	if err != nil {
		t.Fatalf("createPlugin() expected no error, actual %v", err)
	}
	defer os.RemoveAll(dirPath)

	tests := []struct {
		name        string
		address     string
		storeConfig rc.StorePluginConfig
		expectedErr bool
	}{
		{
			name:        "empty config",
			storeConfig: rc.StorePluginConfig{},
			expectedErr: true,
		},
		{
			name:    "valid config",
			address: dirPath,
			storeConfig: rc.StorePluginConfig{
				"name": storeName,
			},
			expectedErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := UpsertStoreMap("", tt.address, storeName, testNamespace, tt.storeConfig)
			if tt.expectedErr != (err != nil) {
				t.Fatalf("expected error: %v, got: %v", tt.expectedErr, err)
			}
		})
	}
}

func TestCreateStoreConfig(t *testing.T) {
	tests := []struct {
		name              string
		raw               []byte
		source            *configv1beta1.PluginSource
		expectedErr       bool
		expectedStoreName string
	}{
		{
			name:        "invalid raw",
			raw:         []byte("invalid\n"),
			expectedErr: true,
		},
		{
			name:              "valid raw",
			raw:               []byte("{\"name\": \"storeName\"}"),
			source:            &configv1beta1.PluginSource{},
			expectedErr:       false,
			expectedStoreName: storeName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := CreateStoreConfig(tt.raw, storeName, tt.source)
			if tt.expectedErr != (err != nil) {
				t.Fatalf("expected error: %v, got: %v", tt.expectedErr, err)
			}
			if _, ok := config[types.Name]; !ok {
				config[types.Name] = ""
			}
			if config[types.Name] != tt.expectedStoreName {
				t.Fatalf("expected store name: %s, got: %s", tt.expectedStoreName, config[types.Name])
			}
		})
	}
}
