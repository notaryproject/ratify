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
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify-verifier-go/cosign"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"oras.land/oras-go/v2/registry"

	"github.com/notaryproject/ratify/v2/internal/verifier"
)

const (
	verifierTypeCosign = "cosign"
	artifactTypeCosign = "application/vnd.dev.cosign.artifact.sig.v1+json"
)

// Verifier implements the [ratify.Verifier] interface for Cosign signatures
// with support for scoped verifiers per registry scope. It wraps multiple
// [cosign.Verifier] instances, each associated with specific scopes
// (registries or repositories).
//
// The verifier supports three types of scope patterns:
//   - Wildcard registries: "*.example.com" matches any subdomain of example.com
//   - Specific registries: "registry.example.com" matches only that registry
//   - Repository paths: "registry.example.com/namespace/repo" matches a
//     specific repository
//
// Scope matching follows a precedence order from most specific to least
// specific:
//  1. Exact repository match
//  2. Exact registry match
//  3. Wildcard registry match
type Verifier struct {
	name       string
	wildcard   map[string]*cosign.Verifier
	registry   map[string]*cosign.Verifier
	repository map[string]*cosign.Verifier
}

// ScopedOptions defines the configuration options for a scoped
// [cosign.Verifier].
type ScopedOptions struct {
	// Scopes is a list of registry scopes to be used by the Cosign verifier.
	// Required.
	Scopes []string `json:"scopes"`

	// CertificateIdentity is the identity to be used for keyless verification.
	// Optional.
	CertificateIdentity string `json:"certificateIdentity,omitempty"`

	// CertificateIdentityRegex is a regex pattern to match the certificate.
	// Optional.
	CertificateIdentityRegex string `json:"certificateIdentityRegex,omitempty"`

	// CertificateOIDCIssuer is the OIDC issuer URL to be used for keyless
	// verification. Optional.
	CertificateOIDCIssuer string `json:"certificateOIDCIssuer,omitempty"`

	// CertificateOIDCIssuerRegex is a regex pattern to match the OIDC issuer.
	// Optional.
	CertificateOIDCIssuerRegex string `json:"certificateOIDCIssuerRegex,omitempty"`

	// IgnoreTLog indicates whether to ignore the transparency log during
	// verification. Optional.
	IgnoreTLog bool `json:"ignoreTLog,omitempty"`

	// IgnoreCTLog indicates whether to ignore the certificate transparency log
	// during verification. Optional.
	IgnoreCTLog bool `json:"ignoreCTLog,omitempty"`
}

// Options contains the configuration options for creating a [Verifier].
type Options struct {
	// TrustPolicies is a list of trust policies to create a [cosign.Verifier]
	// per scope. Required.
	TrustPolicies []*ScopedOptions `json:"trustPolicies"`
}

func init() {
	verifier.RegisterVerifierFactory(verifierTypeCosign, NewVerifier)
}

// NewVerifier creates a new scoped Cosign verifier instance based on the
// provided options.
func NewVerifier(opts *verifier.NewOptions, globalScopes []string) (ratify.Verifier, error) {
	if opts == nil {
		return nil, fmt.Errorf("verifier options cannot be nil")
	}
	if opts.Name == "" {
		return nil, fmt.Errorf("verifier name cannot be empty")
	}

	raw, err := json.Marshal(opts.Parameters)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal verifier parameters: %w", err)
	}

	var params Options
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, fmt.Errorf("failed to unmarshal verifier parameters: %w", err)
	}
	if len(params.TrustPolicies) == 0 {
		return nil, fmt.Errorf("at least one trust policy must be provided")
	}

	scopedVerifier := &Verifier{
		name:       opts.Name,
		wildcard:   make(map[string]*cosign.Verifier),
		registry:   make(map[string]*cosign.Verifier),
		repository: make(map[string]*cosign.Verifier),
	}

	for _, trustPolicy := range params.TrustPolicies {
		if trustPolicy == nil {
			return nil, fmt.Errorf("trust policy cannot be nil")
		}
		if len(trustPolicy.Scopes) == 0 {
			trustPolicy.Scopes = globalScopes
		}

		verifierOpts, err := toVerifierOptions(trustPolicy, opts.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to convert trust policy options: %w", err)
		}
		verifier, err := cosign.NewVerifier(verifierOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to create verifier for trust policy: %w", err)
		}

		// Register the verifier for each scope in the trust policy
		for _, scope := range trustPolicy.Scopes {
			if scope == "" {
				return nil, fmt.Errorf("scope cannot be empty")
			}

			if err := scopedVerifier.registerVerifier(scope, verifier); err != nil {
				return nil, fmt.Errorf("failed to register verifier for scope %q: %w", scope, err)
			}
		}
	}

	return scopedVerifier, nil
}

// Name returns the name of the verifier.
func (v *Verifier) Name() string {
	return v.name
}

// Type returns the type of the verifier which is always "cosign".
func (v *Verifier) Type() string {
	return verifierTypeCosign
}

// Verifiable checks if the artifact is verifiable by the Cosign verifier.
func (v *Verifier) Verifiable(artifact ocispec.Descriptor) bool {
	// All scoped verifiers are Cosign verifiers, so we can check the general
	// Cosign signature criteria
	return artifact.ArtifactType == artifactTypeCosign && artifact.MediaType == ocispec.MediaTypeImageManifest
}

// Verify routes the verification request to the appropriate scoped verifier
// based on the artifact's repository reference.
func (v *Verifier) Verify(ctx context.Context, opts *ratify.VerifyOptions) (*ratify.VerificationResult, error) {
	verifier, err := v.matchVerifier(opts.Repository)
	if err != nil {
		return nil, fmt.Errorf("trust policy is not configured for repository %q: %w", opts.Repository, err)
	}

	return verifier.Verify(ctx, opts)
}

// matchVerifier finds the appropriate verifier for the given repository.
func (v *Verifier) matchVerifier(repository string) (*cosign.Verifier, error) {
	ref, err := registry.ParseReference(repository)
	if err != nil {
		return nil, fmt.Errorf("failed to parse repository reference %q: %w", repository, err)
	}

	repo := ref.Registry + "/" + ref.Repository
	if verifier, ok := v.repository[repo]; ok {
		return verifier, nil
	}

	registry := ref.Registry
	if verifier, ok := v.registry[registry]; ok {
		return verifier, nil
	}

	if _, after, ok := strings.Cut(ref.Registry, "."); ok {
		if verifier, ok := v.wildcard[after]; ok {
			return verifier, nil
		}
	}

	return nil, fmt.Errorf("no verifier configured for the repository %q", repository)
}

// registerVerifier registers a verifier for a given scope.
func (v *Verifier) registerVerifier(scope string, verifier *cosign.Verifier) error {
	if scope == "" {
		return fmt.Errorf("scope cannot be empty")
	}
	if verifier == nil {
		return fmt.Errorf("verifier cannot be nil")
	}

	if strings.Contains(scope, "/") {
		return v.registerRepository(scope, verifier)
	}
	return v.registerRegistry(scope, verifier)
}

// registerRepository registers a verifier for a specific repository scope.
// The scope must be a valid repository path without wildcards, tags, or digests.
func (v *Verifier) registerRepository(scope string, verifier *cosign.Verifier) error {
	if strings.Contains(scope, "*") {
		return fmt.Errorf("invalid scope %q: scope cannot contain wildcard for repository", scope)
	}
	ref, err := registry.ParseReference(scope)
	if err != nil {
		return fmt.Errorf("invalid scope %q: %w", scope, err)
	}
	if ref.Reference != "" {
		return fmt.Errorf("invalid scope %q: scope cannot contain a tag or digest", scope)
	}

	if _, ok := v.repository[scope]; ok {
		return fmt.Errorf("duplicate repository scope %q detected", scope)
	}
	v.repository[scope] = verifier
	return nil
}

// registerRegistry registers a verifier for a given registry scope.
// It supports both exact registry matches and wildcard registry matches.
// The scope can be a specific registry (e.g., "registry.example.com") or a
// wildcard registry (e.g., "*.example.com").
func (v *Verifier) registerRegistry(scope string, verifier *cosign.Verifier) error {
	ref := registry.Reference{
		Registry: scope,
	}
	if err := ref.ValidateRegistry(); err != nil {
		return fmt.Errorf("invalid scope %q: %w", scope, err)
	}

	switch strings.Count(scope, "*") {
	case 0:
		if _, ok := v.registry[scope]; ok {
			return fmt.Errorf("duplicate registry scope %q detected", scope)
		}
		v.registry[scope] = verifier
	case 1:
		// Wildcard registry match
		if !strings.HasPrefix(scope, "*.") {
			return fmt.Errorf("invalid scope %q: wildcard must be at the beginning of the scope", scope)
		}
		scope = scope[2:] // Remove "*." prefix
		if _, ok := v.wildcard[scope]; ok {
			return fmt.Errorf("duplicate wildcard scope %q detected", scope)
		}
		v.wildcard[scope] = verifier
	default:
		return fmt.Errorf("invalid scope %q: scope can only contain one wildcard", scope)
	}

	return nil
}

// toVerifierOptions converts [ScopedOptions] to [cosign.VerifierOptions].
// It creates identity policies for keyless verification based on the
// certificate identity and OIDC issuer configuration.
func toVerifierOptions(s *ScopedOptions, name string) (*cosign.VerifierOptions, error) {
	opts := &cosign.VerifierOptions{
		Name:        name,
		IgnoreTLog:  s.IgnoreTLog,
		IgnoreCTLog: s.IgnoreCTLog,
	}

	if s.CertificateIdentity != "" || s.CertificateIdentityRegex != "" ||
		s.CertificateOIDCIssuer != "" || s.CertificateOIDCIssuerRegex != "" {
		// Create certificate identity using the sigstore verify package
		certIdentity, err := verify.NewShortCertificateIdentity(
			s.CertificateOIDCIssuer,
			s.CertificateOIDCIssuerRegex,
			s.CertificateIdentity,
			s.CertificateIdentityRegex,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create certificate identity: %w", err)
		}

		// Add the certificate identity policy
		opts.IdentityPolicies = []verify.PolicyOption{
			verify.WithCertificateIdentity(certIdentity),
		}
	}

	return opts, nil
}
