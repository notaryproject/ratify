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
	vr "github.com/notaryproject/ratify/v2/pkg/verifier"
)

// VerifierManager is an interface that defines the methods for managing verifiers across different scopes.
type VerifierManager interface {
	// GetVerifiers returns verifiers under the given scope.
	GetVerifiers(scope string) []vr.ReferenceVerifier

	// AddVerifier adds a verifier to the given scope.
	AddVerifier(scope, verifierName string, verifier vr.ReferenceVerifier)

	// DeleteVerifier deletes a verifier from the given scope.
	DeleteVerifier(scope, verifierName string)
}
