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
	"os"
	"path/filepath"
	"testing"
)

const (
	testVersion = "1.0.0"
)

func TestLoad_FromDefaultPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-config")
	if err != nil {
		t.Fatalf("temp dir creation failed %v", err)
	}
	defer os.RemoveAll(tmpDir)

	os.Setenv("RATIFY_CONFIG", tmpDir)
	defer os.Unsetenv("RATIFY_CONFIG")

	fileName := filepath.Join(tmpDir, ConfigFileName)
	content := []byte(`{"store":  { "version": "1.0.0" }}`)
	err = os.WriteFile(fileName, content, 0600)
	if err != nil {
		t.Fatalf("config file creation failed %v", err)
	}

	config, err := Load("")
	if err != nil {
		t.Fatalf("loading config failed %v", err)
	}

	if config.StoresConfig.Version != testVersion {
		t.Fatalf("mismatch of the loaded config expected version %s actual %s", testVersion, config.StoresConfig.Version)
	}

	pluginPath := filepath.Join(tmpDir, PluginsFolder)
	if GetDefaultPluginPath() != pluginPath {
		t.Fatalf("mismatch of the default plugin path expected  %s actual %s", pluginPath, GetDefaultPluginPath())
	}
}

func TestLoad_FromGivenPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-config")
	if err != nil {
		t.Fatalf("temp dir creation failed %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fileName := filepath.Join(tmpDir, ConfigFileName)
	content := []byte(`{"store":  { "version": "1.0.0" }}`)
	err = os.WriteFile(fileName, content, 0600)
	if err != nil {
		t.Fatalf("config file creation failed %v", err)
	}

	config, err := Load(fileName)
	if err != nil {
		t.Fatalf("loading config failed %v", err)
	}

	if config.StoresConfig.Version != testVersion {
		t.Fatalf("mismatch of the loaded config expected version %s actual %s", testVersion, config.StoresConfig.Version)
	}

	if GetDefaultPluginPath() == "" {
		t.Fatalf("default plugin path cannot be empty")
	}
}

func TestLoad_NonExistentConfigFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-config")
	if err != nil {
		t.Fatalf("temp dir creation failed %v", err)
	}

	defer os.RemoveAll(tmpDir)

	fileName := filepath.Join(tmpDir, ConfigFileName)
	_, err = Load(fileName)
	if err == nil {
		t.Fatal("loading config expected to fail")
	}
}

func TestLoad_EmptyConfigSucceeds(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-config")
	if err != nil {
		t.Fatalf("temp dir creation failed %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fileName := filepath.Join(tmpDir, ConfigFileName)
	content := []byte("{}")
	err = os.WriteFile(fileName, content, 0600)
	if err != nil {
		t.Fatalf("config file creation failed %v", err)
	}

	config, err := Load(fileName)
	if err != nil {
		t.Fatalf("loading config failed %v", err)
	}

	if config.StoresConfig.Version != "" {
		t.Fatalf("mismatch of the loaded config expected version %s actual %s", "", config.StoresConfig.Version)
	}
}

func TestLoad_InvalidConfigFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-config")
	if err != nil {
		t.Fatalf("temp dir creation failed %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fileName := filepath.Join(tmpDir, ConfigFileName)
	content := []byte(`"store":  { "version": "1.0.0" }}`)
	err = os.WriteFile(fileName, content, 0600)
	if err != nil {
		t.Fatalf("config file creation failed %v", err)
	}

	if _, err = Load(fileName); err == nil {
		t.Fatalf("loading config is expected to failed")
	}
}

func TestLoad_ComputeHash(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-config")
	if err != nil {
		t.Fatalf("temp dir creation failed %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fileName := filepath.Join(tmpDir, ConfigFileName)
	content := []byte(`{"store":  { "version": "1.0.0" }}`)
	err = os.WriteFile(fileName, content, 0600)
	if err != nil {
		t.Fatalf("config file creation failed %v", err)
	}

	config, err := Load(fileName)
	if err != nil {
		t.Fatalf("loading config failed %v", err)
	}

	if config.StoresConfig.Version != testVersion {
		t.Fatalf("mismatch of the loaded config expected version %s actual %s", testVersion, config.StoresConfig.Version)
	}

	expectedHash := "97660cbbd5c340a844fd5093a7afbccb68673fa2e418cd74528078cf018b60cb"

	if config.fileHash != expectedHash {
		t.Fatalf("Unexpected configuration hash, expected %v, actual %v", expectedHash, config.fileHash)
	}
}

func TestGetHomeDir(t *testing.T) {
	homeDir = "test"
	testOutput := getHomeDir()
	if testOutput != homeDir {
		t.Fatalf("mismatch of home directory: expected %s, actual %s", homeDir, testOutput)
	}
}
