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

package manager

import "testing"

func TestLeaderElectionID(t *testing.T) {
	t.Setenv("RATIFY_NAME", "my-ratify")
	if got, want := leaderElectionID(), "my-ratify.ratify.dev"; got != want {
		t.Errorf("leaderElectionID() = %q, want %q", got, want)
	}
}

func TestManagerOptions(t *testing.T) {
	t.Setenv("RATIFY_NAME", "my-ratify")
	t.Setenv("RATIFY_NAMESPACE", "my-ns")

	t.Run("leader election enabled", func(t *testing.T) {
		opts := managerOptions(true)
		if !opts.LeaderElection {
			t.Error("expected LeaderElection to be true")
		}
		if opts.LeaderElectionID != "my-ratify.ratify.dev" {
			t.Errorf("LeaderElectionID = %q, want %q", opts.LeaderElectionID, "my-ratify.ratify.dev")
		}
		if opts.LeaderElectionNamespace != "my-ns" {
			t.Errorf("LeaderElectionNamespace = %q, want %q", opts.LeaderElectionNamespace, "my-ns")
		}
		if opts.Scheme != scheme {
			t.Error("expected Scheme to be set")
		}
	})

	t.Run("leader election disabled", func(t *testing.T) {
		opts := managerOptions(false)
		if opts.LeaderElection {
			t.Error("expected LeaderElection to be false")
		}
	})
}
