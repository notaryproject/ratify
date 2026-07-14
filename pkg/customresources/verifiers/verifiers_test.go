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

package verifiers

import (
	"context"
	"testing"

	"github.com/notaryproject/ratify/v2/internal/constants"
	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
	"github.com/notaryproject/ratify/v2/pkg/verifier"
)

type mockVerifier struct {
	name string
}

func (v mockVerifier) Name() string {
	return v.name
}

func (v mockVerifier) Type() string {
	return "mockType"
}

func (v mockVerifier) CanVerify(_ context.Context, _ ocispecs.ReferenceDescriptor) bool {
	return true
}

func (v mockVerifier) Verify(_ context.Context, _ common.Reference, _ ocispecs.ReferenceDescriptor, _ referrerstore.ReferrerStore) (verifier.VerifierResult, error) {
	return verifier.VerifierResult{}, nil
}

func (v mockVerifier) GetNestedReferences() []string {
	return nil
}

const (
	namespace1 = constants.EmptyNamespace
	namespace2 = "namespace2"
	name1      = "name1"
	name2      = "name2"
)

var (
	verifier1 = mockVerifier{name: name1}
	verifier2 = mockVerifier{name: name2}
)

func TestVerifiersOperations(t *testing.T) {
	verifiers := NewActiveVerifiers()
	verifiers.AddVerifier(namespace1, verifier1.Name(), verifier1)
	verifiers.AddVerifier(namespace1, verifier2.Name(), verifier2)
	verifiers.AddVerifier(namespace2, verifier1.Name(), verifier1)
	verifiers.AddVerifier(namespace2, verifier2.Name(), verifier2)

	if len(verifiers.GetVerifiers(namespace1)) != 2 {
		t.Fatalf("Expected 2 verifiers, got %d", len(verifiers.GetVerifiers(namespace1)))
	}
	if len(verifiers.GetVerifiers(namespace2)) != 2 {
		t.Fatalf("Expected 2 verifiers, got %d", len(verifiers.GetVerifiers(namespace2)))
	}

	verifiers.DeleteVerifier(namespace2, verifier1.Name())
	if len(verifiers.GetVerifiers(namespace2)) != 1 {
		t.Fatalf("Expected 1 verifier, got %d", len(verifiers.GetVerifiers(namespace2)))
	}

	verifiers.DeleteVerifier(namespace2, verifier2.Name())
	if len(verifiers.GetVerifiers(namespace2)) != 2 {
		t.Fatalf("Expected 2 verifiers, got %d", len(verifiers.GetVerifiers(namespace2)))
	}

	verifiers.DeleteVerifier(namespace1, verifier1.Name())
	if len(verifiers.GetVerifiers(namespace1)) != 1 {
		t.Fatalf("Expected 1 verifier, got %d", len(verifiers.GetVerifiers(namespace1)))
	}

	verifiers.DeleteVerifier(namespace1, verifier2.Name())
	if len(verifiers.GetVerifiers(namespace1)) != 0 {
		t.Fatalf("Expected 0 verifiers, got %d", len(verifiers.GetVerifiers(namespace1)))
	}
}
