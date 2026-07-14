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
	"sync"

	"github.com/notaryproject/ratify/v2/internal/constants"
	vr "github.com/notaryproject/ratify/v2/pkg/verifier"
)

// ActiveVerifiers implements VerifierManger interface.
type ActiveVerifiers struct {
	// The structure of the map is as follows:
	// The first level maps from scope to verifiers
	// The second level maps from verifier name to verifier
	// Example:
	// {
	//   "namespace1": {
	//     "verifier1": verifier1,
	//     "verifier2": verifier2
	//   }
	// }
	// Note: Scope is utilized for organizing and isolating verifiers. In a Kubernetes (K8s) environment, the scope can be either a namespace or an empty string ("") for cluster-wide verifiers.
	//scopedVerifiers map[string]map[string]vr.ReferenceVerifier
	scopedVerifiers sync.Map
}

func NewActiveVerifiers() VerifierManager {
	return &ActiveVerifiers{}
}

// GetVerifiers implements the VerifierManager interface.
// It returns a list of verifiers for the given scope. If no verifiers are found for the given scope, it returns cluster-wide verifiers.
func (v *ActiveVerifiers) GetVerifiers(scope string) []vr.ReferenceVerifier {
	verifiers := []vr.ReferenceVerifier{}
	if scopedVerifier, ok := v.scopedVerifiers.Load(scope); ok {
		for _, verifier := range scopedVerifier.(map[string]vr.ReferenceVerifier) {
			verifiers = append(verifiers, verifier)
		}
	}
	if len(verifiers) == 0 && scope != constants.EmptyNamespace {
		if clusterVerifier, ok := v.scopedVerifiers.Load(constants.EmptyNamespace); ok {
			for _, verifier := range clusterVerifier.(map[string]vr.ReferenceVerifier) {
				verifiers = append(verifiers, verifier)
			}
		}
	}
	return verifiers
}

// AddVerifier fulfills the VerifierManager interface.
// It adds the given verifier under the given scope.
func (v *ActiveVerifiers) AddVerifier(scope, verifierName string, verifier vr.ReferenceVerifier) {
	scopedVerifier, _ := v.scopedVerifiers.LoadOrStore(scope, make(map[string]vr.ReferenceVerifier))
	scopedVerifier.(map[string]vr.ReferenceVerifier)[verifierName] = verifier
}

// DeleteVerifier fulfills the VerifierManager interface.
// It deletes the verfier of the given name under the given scope.
func (v *ActiveVerifiers) DeleteVerifier(scope, verifierName string) {
	if scopedVerifier, ok := v.scopedVerifiers.Load(scope); ok {
		delete(scopedVerifier.(map[string]vr.ReferenceVerifier), verifierName)
	}
}
