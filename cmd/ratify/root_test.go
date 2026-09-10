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
	"strings"
	"testing"
)

func TestNewRootCmd(t *testing.T) {
	cmd := newRootCmd()
	if cmd.Use != "ratify" {
		t.Errorf("unexpected root command use: got %q, want %q", cmd.Use, "ratify")
	}
	if !cmd.SilenceUsage {
		t.Error("expected SilenceUsage to be true on the root command")
	}

	wantSubcommands := map[string]bool{"verify": false, "version": false}
	for _, sub := range cmd.Commands() {
		name := strings.Fields(sub.Use)[0]
		if _, ok := wantSubcommands[name]; ok {
			wantSubcommands[name] = true
		}
	}
	for name, found := range wantSubcommands {
		if !found {
			t.Errorf("expected root command to register subcommand %q", name)
		}
	}
}
