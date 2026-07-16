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

package skel

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
	sp "github.com/notaryproject/ratify/v2/pkg/referrerstore/plugin"
	"github.com/notaryproject/ratify/v2/pkg/verifier/plugin"
	"github.com/notaryproject/ratify/v2/pkg/verifier/types"

	"github.com/notaryproject/ratify/v2/pkg/verifier"

	// This import is required to utilize the oras built-in referrer store
	_ "github.com/notaryproject/ratify/v2/pkg/referrerstore/oras"
	"github.com/notaryproject/ratify/v2/pkg/utils"
)

const (
	skelPluginName = "skel-test-case"
	sampleName     = "sample"
)

var dirPath string

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func setup() {
	dirPath, _ = utils.CreatePlugin(sampleName)
}

func teardown() {
	os.RemoveAll(dirPath)
}

func TestPluginMain_VerifyReference_ReturnsExpected(t *testing.T) {
	verifyReference := func(_ *CmdArgs, _ common.Reference, referenceDescriptor ocispecs.ReferenceDescriptor, referrerStore referrerstore.ReferrerStore) (*verifier.VerifierResult, error) {
		if referenceDescriptor.ArtifactType != "test-type" {
			t.Fatalf("expected artifact type %s actual %s", "test-type", referenceDescriptor.ArtifactType)
		}

		if referrerStore.Name() != "sample" {
			t.Fatalf("expected store name %s actual %s", "sample", referrerStore.Name())
		}

		// the parsed pluginBinDirs should include the data that was provided by Ratify, plus the default (currently assumed to be "")
		expectedPluginBinDirs := []string{dirPath, ""}
		pluginStore := referrerStore.(*sp.StorePlugin)
		actualPluginBinDirs := pluginStore.GetPath()
		if !reflect.DeepEqual(expectedPluginBinDirs, actualPluginBinDirs) {
			t.Fatalf("expected plugin bin dirs %#v actual %#v", expectedPluginBinDirs, actualPluginBinDirs)
		}

		return &verifier.VerifierResult{IsSuccess: true}, nil
	}

	environment := map[string]string{
		plugin.CommandEnvKey: plugin.VerifyCommand,
		plugin.VersionEnvKey: "1.0.0",
		plugin.SubjectEnvKey: "localhost:5000/net-monitor:v1@sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb",
	}

	stdinData := fmt.Sprintf(`{ "storeConfig" : {"store": {"name":"sample", "some": "config"}, "pluginBinDirs": ["%s"]}, "config": {"name": "%s", "some":"config"}, "referenceDesc": {"artifactType": "test-type"}}`, dirPath, skelPluginName)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	pluginContext := &pcontext{
		GetEnviron: func(key string) string { return environment[key] },
		Stdin:      strings.NewReader(stdinData),
		Stdout:     stdout,
		Stderr:     stderr,
	}

	if err := pluginContext.pluginMainCore("", "1.0.0", verifyReference, []string{"1.0.0"}); err != nil {
		t.Fatalf("plugin execution failed %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, `"isSuccess":true`) {
		t.Fatalf("plugin execution failed. expected %v actual %v", "isSuccess: true", out)
	}
}

func TestPluginMain_VerifyReference_CanUseBuiltinStores(t *testing.T) {
	verifyReference := func(_ *CmdArgs, _ common.Reference, _ ocispecs.ReferenceDescriptor, referrerStore referrerstore.ReferrerStore) (*verifier.VerifierResult, error) {
		// expect to find a builtin store and fail if it was configured as a plugin
		if _, ok := referrerStore.(*sp.StorePlugin); ok {
			t.Fatalf("expected store to be builtin")
		}

		return &verifier.VerifierResult{IsSuccess: true}, nil
	}

	environment := map[string]string{
		plugin.CommandEnvKey: plugin.VerifyCommand,
		plugin.VersionEnvKey: "1.0.0",
		plugin.SubjectEnvKey: "localhost:5000/net-monitor:v1@sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb",
	}

	stdinData := `{ "storeConfig" : {"store": {"name":"oras"}}, "config": {"name": "skel-test-case", "some":"config"}, "referenceDesc": {"artifactType": "test-type"}}`
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	pluginContext := &pcontext{
		GetEnviron: func(key string) string { return environment[key] },
		Stdin:      strings.NewReader(stdinData),
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := pluginContext.pluginMainCore("", "1.0.0", verifyReference, []string{"1.0.0"})
	if err != nil {
		t.Fatalf("plugin execution failed %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, `"isSuccess":true`) {
		t.Fatalf("plugin execution failed. expected %v actual %v", "isSuccess: true", out)
	}
}

func TestPluginMain_ErrorCases(t *testing.T) {
	verifyReference := func(_ *CmdArgs, _ common.Reference, _ ocispecs.ReferenceDescriptor, _ referrerstore.ReferrerStore) (*verifier.VerifierResult, error) {
		return nil, fmt.Errorf("simulated error")
	}
	environment := map[string]string{
		plugin.CommandEnvKey: plugin.VerifyCommand,
		plugin.SubjectEnvKey: "localhost:5000/net-monitor:v1@sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb",
	}

	stdinData := fmt.Sprintf(`{ "storeConfig" : {"store": {"name":"sample", "some": "config"}}, "pluginBinDirs": ["%s"], "config": {"name": "%s", "some":"config"}, "referenceDesc": {"artifactType": "test-type"}}`, dirPath, skelPluginName)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	pluginContext := &pcontext{
		GetEnviron: func(key string) string { return environment[key] },
		Stdin:      strings.NewReader(stdinData),
		Stdout:     stdout,
		Stderr:     stderr,
	}

	if err := pluginContext.pluginMainCore("", "1.0.0", verifyReference, []string{"1.0.0"}); err == nil || err.Code != types.ErrMissingEnvironmentVariables {
		t.Fatalf("plugin execution expected to fail with error code %d", types.ErrMissingEnvironmentVariables)
	}

	environment[plugin.VersionEnvKey] = "1.0.0"
	environment[plugin.SubjectEnvKey] = "localhost&300"

	if err := pluginContext.pluginMainCore("", "1.0.0", verifyReference, []string{"1.0.0"}); err == nil || err.Code != types.ErrArgsParsingFailure {
		t.Fatalf("plugin execution expected to fail with error code %d for invalid subject", types.ErrArgsParsingFailure)
	}

	environment[plugin.SubjectEnvKey] = "localhost:5000/net-monitor:v1@sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb"
	environment[plugin.VersionEnvKey] = "2.0.0"
	if err := pluginContext.pluginMainCore("", "1.0.0", verifyReference, []string{"1.0.0"}); err == nil || err.Code != types.ErrVersionNotSupported {
		t.Fatalf("plugin execution expected to fail with error code %d for unsupported version", types.ErrVersionNotSupported)
	}

	environment[plugin.VersionEnvKey] = "1.0.0"

	stdinData = fmt.Sprintf(`"storeConfig" : {"store": {"name":"sample", "some": "config"}, "pluginBinDirs": ["%s"]},"config": {"name": "%s", "some":"config"}, "referenceDesc": {"artifactType": "test-type"}}`, dirPath, skelPluginName)
	pluginContext.Stdin = strings.NewReader(stdinData)
	if err := pluginContext.pluginMainCore("", "1.0.0", verifyReference, []string{"1.0.0"}); err == nil || err.Code != types.ErrConfigParsingFailure {
		t.Fatalf("plugin execution expected to fail with error code %d for invalid config", types.ErrConfigParsingFailure)
	}

	stdinData = fmt.Sprintf(`{"storeConfig" : {"store": {"name":"sample", "some": "config"}, "pluginBinDirs": ["%s"]}, "config": {"some":"config"}, "referenceDesc": {"artifactType": "test-type"}}`, dirPath)
	pluginContext.Stdin = strings.NewReader(stdinData)
	if err := pluginContext.pluginMainCore("", "1.0.0", verifyReference, []string{"1.0.0"}); err == nil || err.Code != types.ErrInvalidVerifierConfig {
		t.Fatalf("plugin execution expected to fail with error code %d for missing verifier name", types.ErrInvalidVerifierConfig)
	}

	environment[plugin.CommandEnvKey] = "unknown"
	stdinData = fmt.Sprintf(`{"storeConfig" : {"store": {"name":"sample", "some": "config"}, "pluginBinDirs": ["%s"]},  "config": {"name": "skel-test-case", "some":"config"}, "referenceDesc": {"artifactType": "test-type"}}`, dirPath)
	pluginContext.Stdin = strings.NewReader(stdinData)
	if err := pluginContext.pluginMainCore("", "1.0.0", verifyReference, []string{"1.0.0"}); err == nil || err.Code != types.ErrUnknownCommand {
		t.Fatalf("plugin execution expected to fail with error code %d for invalid command, actual err :%v", types.ErrUnknownCommand, err)
	}

	environment[plugin.CommandEnvKey] = plugin.VerifyCommand
	stdinData = fmt.Sprintf(`{"storeConfig" : {"store": {"name":"sample", "some": "config"}, "pluginBinDirs": ["%s"]}, "config": {"name": "skel-test-case", "some":"config"}, "referenceDesc": {"artifactType": "test-type"}}`, dirPath)
	pluginContext.Stdin = strings.NewReader(stdinData)
	if err := pluginContext.pluginMainCore("", "1.0.0", verifyReference, []string{"1.0.0"}); err == nil || err.Code != types.ErrPluginCmdFailure {
		t.Fatalf("plugin execution expected to fail with error code %d for cmd failure", types.ErrPluginCmdFailure)
	}
}
