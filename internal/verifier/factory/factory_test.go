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

package factory

import (
	"testing"

	"github.com/notaryproject/ratify-go"
)

const (
	testType = "test-type"
	testName = "test-name"
)

func createVerifier(_ *NewVerifierOptions, _ []string) (ratify.Verifier, error) {
	return nil, nil
}
func TestRegisterVerifierFactory(t *testing.T) {
	t.Run("Registering an empty type", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected panic when registering an empty type, but did not panic")
			}
		}()
		RegisterVerifierFactory("", createVerifier)
	})

	t.Run("Registering a nil factory function", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected panic when registering a nil factory function, but did not panic")
			}
		}()
		RegisterVerifierFactory(testType, nil)
	})

	t.Run("Registering a valid factory function", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Did not expect panic when registering a valid factory function, but got: %v", r)
			}
			delete(registeredVerifiers, "test-type")
		}()
		RegisterVerifierFactory(testType, createVerifier)
	})

	t.Run("Registering a duplicate type", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected panic when registering a duplicate type, but did not panic")
			}
			delete(registeredVerifiers, testType)
		}()
		RegisterVerifierFactory(testType, createVerifier)
		RegisterVerifierFactory(testType, createVerifier)
	})
}

func TestNewVerifier(t *testing.T) {
	t.Run("Creating a verifier with empty name or type", func(t *testing.T) {
		_, err := NewVerifier(&NewVerifierOptions{Name: "", Type: testType}, nil)
		if err == nil {
			t.Errorf("Expected error when creating a verifier with empty name, but got none")
		}

		_, err = NewVerifier(&NewVerifierOptions{Name: testName, Type: ""}, nil)
		if err == nil {
			t.Errorf("Expected error when creating a verifier with empty type, but got none")
		}
	})

	t.Run("Creating a verifier with unregistered type", func(t *testing.T) {
		_, err := NewVerifier(&NewVerifierOptions{Name: testName, Type: "unregistered-type"}, nil)
		if err == nil {
			t.Errorf("Expected error when creating a verifier with unregistered type, but got none")
		}
	})

	t.Run("Creating a verifier with registered type", func(t *testing.T) {
		RegisterVerifierFactory(testType, createVerifier)
		defer func() {
			delete(registeredVerifiers, testType)
		}()

		opts := &NewVerifierOptions{Name: testName, Type: testType}
		_, err := NewVerifier(opts, nil)
		if err != nil {
			t.Errorf("Did not expect error when creating a verifier with registered type, but got: %v", err)
		}
	})
}
