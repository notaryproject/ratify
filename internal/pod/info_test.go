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

package pod

import (
	"os"
	"testing"
)

func TestGetNamespace(t *testing.T) {
	// Test case 1: Environment variable "RATIFY_NAMESPACE" is not set
	t.Run("Environment variable not set", func(t *testing.T) {
		expected := "gatekeeper-system"
		actual := Namespace()
		if actual != expected {
			t.Errorf("Expected namespace to be %q, but got %q", expected, actual)
		}
	})

	// Test case 2: Environment variable "RATIFY_NAMESPACE" is set
	t.Run("Environment variable set", func(t *testing.T) {
		// Set the environment variable
		err := os.Setenv("RATIFY_NAMESPACE", "custom-namespace")
		if err != nil {
			t.Fatal("Failed to set environment variable")
		}

		expected := "custom-namespace"
		actual := Namespace()
		if actual != expected {
			t.Errorf("Expected namespace to be %q, but got %q", expected, actual)
		}

		// Clean up the environment variable after the test
		err = os.Unsetenv("RATIFY_NAMESPACE")
		if err != nil {
			t.Fatal("Failed to unset environment variable")
		}
	})
}

func TestGetServiceName(t *testing.T) {
	// Test case 1: Environment variable "RATIFY_NAME" is not set
	t.Run("Environment variable not set", func(t *testing.T) {
		// Clear any existing value of the environment variable
		err := os.Unsetenv("RATIFY_NAME")
		if err != nil {
			t.Fatal("Failed to unset environment variable")
		}

		expected := "ratify-gatekeeper-provider"
		actual := ServiceName()
		if actual != expected {
			t.Errorf("Expected service name to be %q, but got %q", expected, actual)
		}
	})

	// Test case 2: Environment variable "RATIFY_NAME" is set
	t.Run("Environment variable set", func(t *testing.T) {
		// Set the environment variable
		err := os.Setenv("RATIFY_NAME", "custom-service-name")
		if err != nil {
			t.Fatal("Failed to set environment variable")
		}

		expected := "custom-service-name"
		actual := ServiceName()
		if actual != expected {
			t.Errorf("Expected service name to be %q, but got %q", expected, actual)
		}

		// Clean up the environment variable after the test
		err = os.Unsetenv("RATIFY_NAME")
		if err != nil {
			t.Fatal("Failed to unset environment variable")
		}
	})
}
