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
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestExecutePluginSuccess(t *testing.T) {
	pluginPath := writePluginScript(t, `#!/bin/sh
echo "info: starting" >&2
echo '{"ok":true}'
echo "warn: done" >&2
`)

	executor := &DefaultExecutor{}
	output, err := executor.ExecutePlugin(context.Background(), pluginPath, []string{"arg"}, []byte("stdin"), []string{"RATIFY_TEST=value"})
	if err != nil {
		t.Fatalf("expected plugin execution to succeed: %v", err)
	}
	if string(output) != `{"ok":true}` {
		t.Fatalf("expected JSON output, got %s", output)
	}
}

func TestExecutePluginError(t *testing.T) {
	pluginPath := writePluginScript(t, `#!/bin/sh
echo "stdout failure"
echo "stderr failure" >&2
exit 7
`)

	executor := &DefaultExecutor{}
	_, err := executor.ExecutePlugin(context.Background(), pluginPath, nil, nil, nil)
	if err == nil {
		t.Fatal("expected plugin execution error")
	}
	if !strings.Contains(err.Error(), "stderr failure") {
		t.Fatalf("expected stderr in error, got %v", err)
	}
	if !strings.Contains(err.Error(), "stdout failure") {
		t.Fatalf("expected stdout in error, got %v", err)
	}
}

func TestDefaultExecutorFindInPaths(t *testing.T) {
	pluginPath := writePluginScript(t, "#!/bin/sh\n")
	dir, name := splitPluginPath(t, pluginPath)

	executor := &DefaultExecutor{}
	got, err := executor.FindInPaths(name, []string{dir})
	if err != nil {
		t.Fatalf("expected plugin to be found: %v", err)
	}
	if got != pluginPath {
		t.Fatalf("expected %q, got %q", pluginPath, got)
	}
}

func TestParsePluginOutputAdditional(t *testing.T) {
	stdout := bytes.NewBufferString("plain stdout\n{\"status\":\"ok\"}\n")
	stderr := bytes.NewBufferString("warn: warning message\nnot json {broken\n")

	output, messages := parsePluginOutput(stdout, stderr)
	if string(output) != `{"status":"ok"}` {
		t.Fatalf("expected parsed JSON output, got %s", output)
	}
	if len(messages) != 2 {
		t.Fatalf("expected two plugin messages, got %d", len(messages))
	}
}
