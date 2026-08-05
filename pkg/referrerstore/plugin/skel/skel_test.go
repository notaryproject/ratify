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
	"strings"
	"testing"

	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore/plugin"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore/types"
	"github.com/notaryproject/ratify/v2/pkg/utils"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

const skelPluginName = "skel-test-case"

var dirPath string
var testStdinData string

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func setup() {
	dirPath, _ = utils.CreatePlugin(skelPluginName)
	testStdinData = fmt.Sprintf(`{ "name":"skel-test-case", "some": "config","pluginBinDirs": ["%s"]}`, dirPath)
}

func teardown() {
	os.RemoveAll(dirPath)
}

func TestPluginMain_GetBlobContent_ReturnsExpected(t *testing.T) {
	getBlobContent := func(_ *CmdArgs, _ common.Reference, digest digest.Digest) ([]byte, error) {
		return []byte(digest.String()), nil
	}
	environment := map[string]string{
		plugin.CommandEnvKey: plugin.GetBlobContentCommand,
		plugin.VersionEnvKey: "1.0.0",
		plugin.ArgsEnvKey:    "digest=sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb",
		plugin.SubjectEnvKey: "localhost:5000/net-monitor:v1@sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb",
	}

	stdinData := testStdinData
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	pluginContext := &pcontext{
		GetEnviron: func(key string) string { return environment[key] },
		Stdin:      strings.NewReader(stdinData),
		Stdout:     stdout,
		Stderr:     stderr,
	}

	if err := pluginContext.pluginMainCore("", "1.0.0", nil, getBlobContent, nil, nil, []string{"1.0.0"}); err != nil {
		t.Fatalf("plugin execution failed %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb") {
		t.Fatalf("plugin execution failed. expected %v actual %v", "sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb", out)
	}
}

func TestPluginMain_GetReferenceManifest_ReturnsExpected(t *testing.T) {
	getReferenceManifest := func(_ *CmdArgs, _ common.Reference, _ digest.Digest) (ocispecs.ReferenceManifest, error) {
		return ocispecs.ReferenceManifest{
			ArtifactType: "test-type",
		}, nil
	}

	environment := map[string]string{
		plugin.CommandEnvKey: plugin.GetRefManifestCommand,
		plugin.VersionEnvKey: "1.0.0",
		plugin.ArgsEnvKey:    "digest=sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb",
		plugin.SubjectEnvKey: "localhost:5000/net-monitor:v1@sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb",
	}

	stdinData := testStdinData
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	pluginContext := &pcontext{
		GetEnviron: func(key string) string { return environment[key] },
		Stdin:      strings.NewReader(stdinData),
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := pluginContext.pluginMainCore("", "1.0.0", nil, nil, getReferenceManifest, nil, []string{"1.0.0"})
	if err != nil {
		t.Fatalf("plugin execution failed %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "test-type") {
		t.Fatalf("plugin execution failed. expected %v actual %v", "test-type", out)
	}
}

func TestPluginMain_ListReferrers_ReturnsExpected(t *testing.T) {
	listReferrers := func(_ *CmdArgs, _ common.Reference, _ []string, _ string, _ *ocispecs.SubjectDescriptor) (*referrerstore.ListReferrersResult, error) {
		return &referrerstore.ListReferrersResult{
			NextToken: "next-token",
			Referrers: []ocispecs.ReferenceDescriptor{
				{
					ArtifactType: "test-type",
				},
			},
		}, nil
	}

	environment := map[string]string{
		plugin.CommandEnvKey: plugin.ListReferrersCommand,
		plugin.VersionEnvKey: "1.0.0",
		plugin.ArgsEnvKey:    "nextToken=;artifactTypes=",
		plugin.SubjectEnvKey: "localhost:5000/net-monitor:v1@sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb",
	}

	stdinData := testStdinData
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	pluginContext := &pcontext{
		GetEnviron: func(key string) string { return environment[key] },
		Stdin:      strings.NewReader(stdinData),
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := pluginContext.pluginMainCore("", "1.0.0", listReferrers, nil, nil, nil, []string{"1.0.0"})
	if err != nil {
		t.Fatalf("plugin execution failed %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "test-type") || !strings.Contains(out, "next-token") {
		t.Fatalf("plugin execution failed. expected %v actual %v", "test-type, next-token", out)
	}
}

func TestPluginMain_GetSubjectDesc_ReturnsExpected(t *testing.T) {
	testDigest := digest.FromString("test")
	getSubjectDesc := func(_ *CmdArgs, _ common.Reference) (*ocispecs.SubjectDescriptor, error) {
		return &ocispecs.SubjectDescriptor{Descriptor: v1.Descriptor{Digest: testDigest}}, nil
	}

	environment := map[string]string{
		plugin.CommandEnvKey: plugin.GetSubjectDescriptor,
		plugin.VersionEnvKey: "1.0.0",
		plugin.SubjectEnvKey: "localhost:5000/net-monitor:v1",
	}

	stdinData := testStdinData
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	pluginContext := &pcontext{
		GetEnviron: func(key string) string { return environment[key] },
		Stdin:      strings.NewReader(stdinData),
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := pluginContext.pluginMainCore("", "1.0.0", nil, nil, nil, getSubjectDesc, []string{"1.0.0"})
	if err != nil {
		t.Fatalf("plugin execution failed %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, testDigest.String()) {
		t.Fatalf("plugin execution failed. expected %v actual %v", testDigest.String(), out)
	}
}

func TestPluginMain_ErrorCases(t *testing.T) {
	getBlobContent := func(_ *CmdArgs, _ common.Reference, _ digest.Digest) ([]byte, error) {
		return nil, fmt.Errorf("simulated error")
	}
	environment := map[string]string{
		plugin.CommandEnvKey: plugin.GetBlobContentCommand,
		plugin.ArgsEnvKey:    "digest=sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb",
		plugin.SubjectEnvKey: "localhost:5000/net-monitor:v1@sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb",
	}

	stdinData := testStdinData
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	pluginContext := &pcontext{
		GetEnviron: func(key string) string { return environment[key] },
		Stdin:      strings.NewReader(stdinData),
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := pluginContext.pluginMainCore("", "1.0.0", nil, getBlobContent, nil, nil, []string{"1.0.0"})
	if err == nil || err.Code != types.ErrMissingEnvironmentVariables {
		t.Fatalf("plugin execution expected to fail with error code %d", types.ErrMissingEnvironmentVariables)
	}

	environment[plugin.VersionEnvKey] = "1.0.0"
	environment[plugin.SubjectEnvKey] = "localhost&300"

	err = pluginContext.pluginMainCore("", "1.0.0", nil, getBlobContent, nil, nil, []string{"1.0.0"})
	if err == nil || err.Code != types.ErrArgsParsingFailure {
		t.Fatalf("plugin execution expected to fail with error code %d for invalid subject", types.ErrArgsParsingFailure)
	}

	environment[plugin.SubjectEnvKey] = "localhost:5000/net-monitor:v1@sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb"
	environment[plugin.VersionEnvKey] = "2.0.0"
	err = pluginContext.pluginMainCore("", "1.0.0", nil, getBlobContent, nil, nil, []string{"1.0.0"})
	if err == nil || err.Code != types.ErrVersionNotSupported {
		t.Fatalf("plugin execution expected to fail with error code %d for unsupported version", types.ErrVersionNotSupported)
	}

	environment[plugin.VersionEnvKey] = "1.0.0"

	stdinData = ` "name":"skel-test-case", "some": "config" }`
	pluginContext.Stdin = strings.NewReader(stdinData)
	err = pluginContext.pluginMainCore("", "1.0.0", nil, getBlobContent, nil, nil, []string{"1.0.0"})
	if err == nil || err.Code != types.ErrConfigParsingFailure {
		t.Fatalf("plugin execution expected to fail with error code %d for invalid config, actual error: %s", types.ErrConfigParsingFailure, err)
	}

	stdinData = ` {"some": "config" }`
	pluginContext.Stdin = strings.NewReader(stdinData)
	err = pluginContext.pluginMainCore("", "1.0.0", nil, getBlobContent, nil, nil, []string{"1.0.0"})
	if err == nil || err.Code != types.ErrInvalidStoreConfig {
		t.Fatalf("plugin execution expected to fail with error code %d for missing store name", types.ErrInvalidStoreConfig)
	}

	environment[plugin.CommandEnvKey] = "unknown"
	stdinData = testStdinData
	pluginContext.Stdin = strings.NewReader(stdinData)
	err = pluginContext.pluginMainCore("", "1.0.0", nil, getBlobContent, nil, nil, []string{"1.0.0"})
	if err == nil || err.Code != types.ErrUnknownCommand {
		t.Fatalf("plugin execution expected to fail with error code %d for invalid command", types.ErrUnknownCommand)
	}

	environment[plugin.CommandEnvKey] = plugin.GetBlobContentCommand
	stdinData = testStdinData
	pluginContext.Stdin = strings.NewReader(stdinData)
	err = pluginContext.pluginMainCore("", "1.0.0", nil, getBlobContent, nil, nil, []string{"1.0.0"})
	if err == nil || err.Code != types.ErrPluginCmdFailure {
		t.Fatalf("plugin execution expected to fail with error code %d for cmd failure", types.ErrPluginCmdFailure)
	}
}

func TestPluginMain_GetBlobContent_ErrorCases(t *testing.T) {
	getBlobContent := func(_ *CmdArgs, _ common.Reference, digest digest.Digest) ([]byte, error) {
		return []byte(digest.String()), nil
	}
	environment := map[string]string{
		plugin.CommandEnvKey: plugin.GetBlobContentCommand,
		plugin.VersionEnvKey: "1.0.0",
		plugin.ArgsEnvKey:    "digest1=sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb",
		plugin.SubjectEnvKey: "localhost:5000/net-monitor:v1@sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb",
	}

	stdinData := testStdinData
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	pluginContext := &pcontext{
		GetEnviron: func(key string) string { return environment[key] },
		Stdin:      strings.NewReader(stdinData),
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := pluginContext.pluginMainCore("", "1.0.0", nil, getBlobContent, nil, nil, []string{"1.0.0"})
	if err == nil || err.Code != types.ErrArgsParsingFailure {
		t.Fatalf("plugin execution expected to fail with error code %d for invalid arg", types.ErrArgsParsingFailure)
	}

	stdinData = testStdinData
	pluginContext.Stdin = strings.NewReader(stdinData)
	environment[plugin.ArgsEnvKey] = "digest=sha256a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb"
	err = pluginContext.pluginMainCore("", "1.0.0", nil, getBlobContent, nil, nil, []string{"1.0.0"})
	if err == nil || err.Code != types.ErrArgsParsingFailure {
		t.Fatalf("plugin execution expected to fail with error code %d for invalid digest", types.ErrArgsParsingFailure)
	}
}

func TestPluginMain_ListReferrers_ErrorCases(t *testing.T) {
	listReferrers := func(_ *CmdArgs, _ common.Reference, _ []string, _ string, _ *ocispecs.SubjectDescriptor) (*referrerstore.ListReferrersResult, error) {
		return &referrerstore.ListReferrersResult{
			NextToken: "next-token",
			Referrers: []ocispecs.ReferenceDescriptor{
				{
					ArtifactType: "test-type",
				},
			},
		}, nil
	}

	environment := map[string]string{
		plugin.CommandEnvKey: plugin.ListReferrersCommand,
		plugin.VersionEnvKey: "1.0.0",
		plugin.ArgsEnvKey:    "nextToken1=;artifactTypes=",
		plugin.SubjectEnvKey: "localhost:5000/net-monitor:v1@sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb",
	}

	stdinData := testStdinData
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	pluginContext := &pcontext{
		GetEnviron: func(key string) string { return environment[key] },
		Stdin:      strings.NewReader(stdinData),
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := pluginContext.pluginMainCore("", "1.0.0", listReferrers, nil, nil, nil, []string{"1.0.0"})
	if err == nil || err.Code != types.ErrArgsParsingFailure {
		t.Fatalf("plugin execution expected to fail with error code %d for invalid arg", types.ErrArgsParsingFailure)
	}
}
