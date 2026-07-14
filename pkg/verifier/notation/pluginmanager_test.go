// Copyright The Ratify Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package notation

import (
	"context"
	"os"
	"testing"
)

const (
	pluginDirectory  = "./pluginmanagertest"
	ignoredDirectory = "notation-ignored"
	ignoredFile      = "ignored.file"
	testPluginName   = "mock.plugin"
)

func TestMain(m *testing.M) {
	err := setupTestFiles()
	code := 1
	if err == nil {
		code = m.Run()
	}
	cleanupTestFiles()
	os.Exit(code)
}

func setupTestFiles() error {
	err := os.Mkdir(pluginDirectory, 0700)
	if err != nil {
		return err
	}

	err = os.Mkdir(pluginDirectory+"/"+ignoredDirectory, 0700)
	if err != nil {
		return err
	}

	err = os.WriteFile(pluginDirectory+"/"+notationPluginPrefix+testPluginName, []byte(""), 0600)
	if err != nil {
		return err
	}

	err = os.WriteFile(pluginDirectory+"/"+ignoredFile, []byte(""), 0600)
	if err != nil {
		return err
	}

	return nil
}

func cleanupTestFiles() {
	os.RemoveAll(pluginDirectory)
}

func TestPluginManagerGet(t *testing.T) {
	pluginManager := NewRatifyPluginManager(pluginDirectory)

	_, err := pluginManager.Get(context.TODO(), testPluginName)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPluginManagerList(t *testing.T) {
	pluginManager := NewRatifyPluginManager(pluginDirectory)

	pluginList, err := pluginManager.List(context.TODO())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(pluginList) != 1 {
		t.Errorf("expected to find exactly one plugin, instead found %d", len(pluginList))
		t.Fatalf("plugin list: %+v", pluginList)
	}

	if pluginList[0] != testPluginName {
		t.Errorf("expected to find plugin named %s, instead found %s", testPluginName, pluginList[0])
	}
}
