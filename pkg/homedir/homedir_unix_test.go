//go:build !windows
// +build !windows

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

package homedir

import "testing"

func TestKey(t *testing.T) {
	if got := Key(); got != "HOME" {
		t.Fatalf("expected HOME, got %q", got)
	}
}

func TestGet(t *testing.T) {
	t.Setenv(Key(), "/tmp/ratify-home")

	if got := Get(); got != "/tmp/ratify-home" {
		t.Fatalf("expected /tmp/ratify-home, got %q", got)
	}
}

func TestGetFallbackToCurrentUser(t *testing.T) {
	t.Setenv(Key(), "")

	if got := Get(); got == "" {
		t.Fatal("expected current user home directory fallback")
	}
}

func TestGetShortcutString(t *testing.T) {
	if got := GetShortcutString(); got != "~" {
		t.Fatalf("expected ~, got %q", got)
	}
}
