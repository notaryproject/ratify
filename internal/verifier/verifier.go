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

package verifier

import (
	"fmt"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify/v2/internal/verifier/factory"
)

// NewVerifiers creates a slice of ratify.Verifier instances based on the
// provided options.
func NewVerifiers(opts []*factory.NewVerifierOptions, globalScopes []string) ([]ratify.Verifier, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("no verifier options provided")
	}
	verifiers := make([]ratify.Verifier, len(opts))
	for idx, opt := range opts {
		verifier, err := factory.NewVerifier(opt, globalScopes)
		if err != nil {
			return nil, err
		}
		verifiers[idx] = verifier
	}
	return verifiers, nil
}
