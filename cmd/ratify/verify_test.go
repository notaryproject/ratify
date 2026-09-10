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
	"os"
	"path/filepath"
	"testing"
)

func TestResolveConfigPath(t *testing.T) {
	t.Run("explicit path takes precedence", func(t *testing.T) {
		t.Setenv("RATIFY_CONFIG", filepath.Join("some", "dir"))
		got, err := resolveConfigPath("/custom/config.json")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "/custom/config.json" {
			t.Errorf("got %q, want %q", got, "/custom/config.json")
		}
	})

	t.Run("RATIFY_CONFIG directory is used", func(t *testing.T) {
		dir := filepath.Join("ratify", "conf")
		t.Setenv("RATIFY_CONFIG", dir)
		got, err := resolveConfigPath("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := filepath.Join(dir, configFileName)
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("default home directory path", func(t *testing.T) {
		t.Setenv("RATIFY_CONFIG", "")
		home, err := os.UserHomeDir()
		if err != nil {
			t.Skipf("cannot determine home directory: %v", err)
		}
		got, err := resolveConfigPath("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := filepath.Join(home, configFileDir, configFileName)
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

func TestLoadExecutor(t *testing.T) {
	t.Run("missing file returns error", func(t *testing.T) {
		_, err := loadExecutor(filepath.Join(t.TempDir(), "does-not-exist.json"))
		if err == nil {
			t.Fatal("expected an error for a missing configuration file")
		}
	})

	t.Run("invalid JSON returns error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
			t.Fatalf("failed to write config: %v", err)
		}
		_, err := loadExecutor(path)
		if err == nil {
			t.Fatal("expected an error for invalid JSON")
		}
	})

	t.Run("empty executors returns error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(`{"executors":[]}`), 0o600); err != nil {
			t.Fatalf("failed to write config: %v", err)
		}
		_, err := loadExecutor(path)
		if err == nil {
			t.Fatal("expected an error when no executors are configured")
		}
	})
}

func TestRunVerify_InvalidOutputFormat(t *testing.T) {
	cmd := newVerifyCmd()
	opts := &verifyOptions{
		subject: "registry.example/repo:v1",
		output:  "yaml",
	}
	if err := runVerify(cmd, opts); err == nil {
		t.Error("expected an error for an unsupported output format")
	}
}

func TestVerifyCmd_RequiresSubject(t *testing.T) {
	cmd := newVerifyCmd()
	cmd.SetOut(new(bytesBuffer))
	cmd.SetErr(new(bytesBuffer))
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err == nil {
		t.Error("expected an error when --subject is not provided")
	}
}

// bytesBuffer is a minimal io.Writer used to discard command output in tests.
type bytesBuffer struct{}

func (*bytesBuffer) Write(p []byte) (int, error) { return len(p), nil }
