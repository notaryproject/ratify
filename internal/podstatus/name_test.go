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

package podstatus

import "testing"

func TestPackUnpackNameRoundTrip(t *testing.T) {
	cases := []struct {
		pod      string
		executor string
	}{
		{"ratify-gatekeeper-provider-7d9f8c-abcde", "default"},
		{"pod-1", "my-executor.with.dots"},
		{"UPPER-Case-Pod", "Executor-With-CAPS"},
		{"p", "e"},
	}
	for _, c := range cases {
		name := PackName(c.pod, c.executor)
		gotPod, gotExec, err := UnpackName(name)
		if err != nil {
			t.Fatalf("UnpackName(%q) returned error: %v", name, err)
		}
		if gotPod != c.pod || gotExec != c.executor {
			t.Errorf("round trip mismatch: PackName(%q,%q)=%q -> (%q,%q)", c.pod, c.executor, name, gotPod, gotExec)
		}
	}
}

func TestPackNameIsDNS1123Compliant(t *testing.T) {
	name := PackName("Pod_Name/With:Weird*Chars", "Executor Name!")
	for _, c := range name {
		valid := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
		if !valid {
			t.Errorf("packed name %q contains invalid DNS-1123 character %q", name, c)
		}
	}
}

func TestPackNameUniquePerPair(t *testing.T) {
	a := PackName("pod-a", "exec")
	b := PackName("pod-b", "exec")
	c := PackName("pod-a", "other")
	if a == b || a == c || b == c {
		t.Errorf("expected unique names, got a=%q b=%q c=%q", a, b, c)
	}
}

func TestUnpackNameInvalid(t *testing.T) {
	if _, _, err := UnpackName("no-separator-but-not-base32!!"); err == nil {
		t.Errorf("expected error for invalid name")
	}
}
