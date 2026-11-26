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
	"context"
	"fmt"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify-go/plugin"

	"github.com/notaryproject/ratify/v2/internal/encoding/jsonutil"
)

// NewOptions holds the options to create a [ratify.Verifier].
type NewOptions struct {
	// Name is the unique identifier of a verifier instance. Required.
	Name string `json:"name"`

	// Type represents a specific implementation of a verifier. Required.
	// Note: there could be multiple verifiers of the same type with different
	//       names.
	Type string `json:"type"`

	// Parameters is additional parameters of the verifier. Optional.
	Parameters any `json:"parameters,omitempty"`
}

// New creates a [ratify.Verifier] instance of a type registered to the
// [plugin.Default] registry. The parameters are passed through to the plugin
// factory as raw JSON. The returned verifier reports the
// ratify_verifier_duration metric for every verification.
func New(opts NewOptions, globalScopes []string) (ratify.Verifier, error) {
	if opts.Name == "" || opts.Type == "" {
		return nil, fmt.Errorf("name or type is not provided in the verifier options")
	}
	params, err := jsonutil.RawMessage(opts.Parameters)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal parameters of verifier %q: %w", opts.Name, err)
	}
	verifier, err := plugin.Default.NewVerifier(context.Background(), opts.Type, plugin.VerifierOptions{
		Name:       opts.Name,
		Parameters: params,
		Scopes:     globalScopes,
	})
	if err != nil {
		return nil, err
	}
	return &instrumentedVerifier{Verifier: verifier}, nil
}

// NewVerifiers creates a slice of [ratify.Verifier] instances based on the
// provided options.
func NewVerifiers(opts []NewOptions, globalScopes []string) ([]ratify.Verifier, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("no verifier options provided")
	}
	verifiers := make([]ratify.Verifier, len(opts))
	for idx, opt := range opts {
		verifier, err := New(opt, globalScopes)
		if err != nil {
			return nil, err
		}
		verifiers[idx] = verifier
	}
	return verifiers, nil
}
