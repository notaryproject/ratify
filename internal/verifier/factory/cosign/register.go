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

package cosign

import (
	"encoding/json"
	"fmt"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify-verifier-go/cosign"
	"github.com/notaryproject/ratify/v2/internal/verifier/factory"
)

const (
	cosignType = "cosign"
)

type options struct {
	// Scopes is a list of registry scopes to be used by the Cosign verifier.
	// Required.
	Scopes []string `json:"scopes"`

	CertificateIdentity string `json:"certificateIdentity,omitempty"`

	CertificateIdentityRegex string `json:"certificateIdentityRegex,omitempty"`

	CertificateOIDCIssuer string `json:"certificateOIDCIssuer,omitempty"`

	CertificateOIDCIssuerRegex string `json:"certificateOIDCIssuerRegex,omitempty"`

	IgnoreTlog bool `json:"ignoreTlog,omitempty"`

	RequireTimestamp bool `json:"requireTimestamp,omitempty"`

	IgnoreCTLog bool `json:"ignoreCTLog,omitempty"`
}

func init() {
	factory.RegisterVerifierFactory(cosignType, func(opts *factory.NewVerifierOptions) (ratify.Verifier, error) {
		raw, err := json.Marshal(opts.Parameters)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal verifier parameters: %w", err)
		}

		var params options
		if err := json.Unmarshal(raw, &params); err != nil {
			return nil, fmt.Errorf("failed to unmarshal verifier parameters: %w", err)
		}

		cosignVerifier, err := cosign.NewVerifier()
		if err != nil {
			return nil, err
		}

		return cosignVerifier, nil
	})
}
