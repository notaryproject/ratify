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

package imageref

import "testing"

func TestNormalize(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Empty reference",
			input:    "",
			expected: "",
		},
		{
			name:     "Official image",
			input:    "nginx",
			expected: "docker.io/library/nginx",
		},
		{
			name:     "Official image with tag",
			input:    "nginx:1.27",
			expected: "docker.io/library/nginx:1.27",
		},
		{
			name:     "Official image with digest",
			input:    "nginx@sha256:abc123",
			expected: "docker.io/library/nginx@sha256:abc123",
		},
		{
			name:     "Docker Hub user image",
			input:    "org/app:v1",
			expected: "docker.io/org/app:v1",
		},
		{
			name:     "Docker Hub user image with nested path",
			input:    "org/team/app:v1",
			expected: "docker.io/org/team/app:v1",
		},
		{
			name:     "Docker Hub official image without library namespace",
			input:    "docker.io/nginx:1.27",
			expected: "docker.io/library/nginx:1.27",
		},
		{
			name:     "Fully qualified Docker Hub image",
			input:    "docker.io/library/nginx:1.27",
			expected: "docker.io/library/nginx:1.27",
		},
		{
			name:     "Registry with domain",
			input:    "registry.example.com/app:v1",
			expected: "registry.example.com/app:v1",
		},
		{
			name:     "Registry with domain and single component repository",
			input:    "registry.example.com/app",
			expected: "registry.example.com/app",
		},
		{
			name:     "Registry with port",
			input:    "registry:5000/notation@sha256:abc123",
			expected: "registry:5000/notation@sha256:abc123",
		},
		{
			name:     "Localhost registry",
			input:    "localhost/app:v1",
			expected: "localhost/app:v1",
		},
		{
			name:     "IPv6 registry",
			input:    "[2001:db8::1]:5000/repo:tag",
			expected: "[2001:db8::1]:5000/repo:tag",
		},
		{
			name:     "Uppercase first component",
			input:    "Registry/app:v1",
			expected: "Registry/app:v1",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := Normalize(test.input)
			if result != test.expected {
				t.Errorf("expected %q, got %q", test.expected, result)
			}
			if again := Normalize(result); again != result {
				t.Errorf("expected normalization to be idempotent, got %q from %q", again, result)
			}
		})
	}
}
