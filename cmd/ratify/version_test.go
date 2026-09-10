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

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/notaryproject/ratify/v2/internal/version"
)

func TestVersionCmd(t *testing.T) {
	origVersion := version.Version
	origTag := version.GitTag
	origCommit := version.GitCommitHash
	origTreeState := version.GitTreeState
	t.Cleanup(func() {
		version.Version = origVersion
		version.GitTag = origTag
		version.GitCommitHash = origCommit
		version.GitTreeState = origTreeState
	})

	version.Version = "v2.0.0-test"
	version.GitTag = "v2.0.0"
	version.GitCommitHash = "abcdef123456"
	version.GitTreeState = "clean"

	cmd := newVersionCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("version command returned unexpected error: %v", err)
	}

	got := out.String()
	for _, want := range []string{"v2.0.0-test", "v2.0.0", "abcdef123456", "clean"} {
		if !strings.Contains(got, want) {
			t.Errorf("version output missing %q; got:\n%s", want, got)
		}
	}
}

func TestVersionCmd_RejectsArgs(t *testing.T) {
	cmd := newVersionCmd()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"unexpected"})
	if err := cmd.Execute(); err == nil {
		t.Error("expected an error when passing arguments to the version command")
	}
}
