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

package executor

import (
	"context"
	"fmt"
	"strings"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify/v2/internal/policyenforcer"
	"github.com/notaryproject/ratify/v2/internal/store"
	"github.com/notaryproject/ratify/v2/internal/verifier"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"oras.land/oras-go/v2/registry"
)

// ScopedOptions contains the configuration options to create a group of plugins
// for the executor under a scope.
type ScopedOptions struct {
	// Scopes defines the scopes for which this executor is responsible.
	// Required.
	Scopes []string `json:"scopes"`

	// Verifiers contains the configuration options for the verifiers. Required.
	Verifiers []verifier.NewOptions `json:"verifiers"`

	// Stores contains the configuration options for the stores. Required.
	Stores []store.NewOptions `json:"stores"`

	// Policy contains the configuration options for the policy enforcer.
	// Optional.
	Policy *policyenforcer.NewOptions `json:"policyEnforcer,omitempty"`
}

// Options contains the configuration options to create a scoped executor.
type Options struct {
	// Executors contains the configuration options for the executor per scope.
	// Each scope can have its own set of verifiers, stores, and policy
	// enforcer. At least one executor must be provided.
	// Required.
	Executors []ScopedOptions `json:"executors"`

	MaxConcurrency int `json:"maxConcurrency,omitempty"`
}

// ScopedExecutor manages multiple ratify.Executor instances, each associated
// with specific scopes (registries or repositories). It provides a mechanism to
// route artifact validation requests to the appropriate executor based on the
// artifact's reference.
//
// The executor supports three types of scope patterns:
//   - Wildcard registries: "*.example.com" matches any subdomain of example.com
//   - Specific registries: "registry.example.com" matches only that registry
//   - Repository paths: "registry.example.com/namespace/repo" matches a
//     specific repository
//
// Note: Top level domain wildcard is also not supported. That is, "*" is not a
// valid pattern.
// Scope matching follows a precedence order from most specific to least
// specific:
//  1. Exact repository match
//  2. Exact registry match
//  3. Wildcard registry match
type ScopedExecutor struct {
	wildcard   map[string]*ratify.Executor
	registry   map[string]*ratify.Executor
	repository map[string]*ratify.Executor
}

// NewScopedExecutor creates a new ScopedExecutor instance based on the provided
// options. It initializes the executor for each scope defined in the options.
// If no executors are provided, it returns an error.
func NewScopedExecutor(opts Options) (*ScopedExecutor, error) {
	if len(opts.Executors) == 0 {
		return nil, fmt.Errorf("at least 1 executor should be provided")
	}
	scopedExecutor := &ScopedExecutor{
		wildcard:   make(map[string]*ratify.Executor),
		registry:   make(map[string]*ratify.Executor),
		repository: make(map[string]*ratify.Executor),
	}

	for _, executorOpts := range opts.Executors {
		if len(executorOpts.Scopes) == 0 {
			return nil, fmt.Errorf("executor options must contain at least one scope")
		}
		executor, err := newExecutor(executorOpts, opts.MaxConcurrency)
		if err != nil {
			return nil, fmt.Errorf("failed to create executor: %w", err)
		}
		for _, scope := range executorOpts.Scopes {
			if err = scopedExecutor.registerExecutor(scope, executor); err != nil {
				return nil, fmt.Errorf("failed to register executor for scope %q: %w", scope, err)
			}
		}
	}
	return scopedExecutor, nil
}

// newExecutor creates a new [ratify.Executor] instance based on the provided
// options.
func newExecutor(opts ScopedOptions, maxConcurrency int) (*ratify.Executor, error) {
	verifiers, err := verifier.NewVerifiers(opts.Verifiers, opts.Scopes)
	if err != nil {
		return nil, err
	}

	storeMux, err := store.New(opts.Stores, opts.Scopes)
	if err != nil {
		return nil, err
	}

	var policy ratify.PolicyEnforcer
	if opts.Policy != nil {
		policy, err = policyenforcer.New(*opts.Policy)
		if err != nil {
			return nil, err
		}
	}

	return ratify.NewExecutor(storeMux, verifiers, policy, maxConcurrency)
}

// ValidateArtifact routes the artifact validation request to the appropriate
// executor based on the artifact's reference. It returns the validation result
// or an error if no matching executor is found.
func (s *ScopedExecutor) ValidateArtifact(ctx context.Context, artifact string) (*ratify.ValidationResult, error) {
	executor, err := s.matchExecutor(artifact)
	if err != nil {
		return nil, fmt.Errorf("failed to match executor for artifact %q: %w", artifact, err)
	}
	opts := ratify.ValidateArtifactOptions{
		Subject: artifact,
	}
	return executor.ValidateArtifact(ctx, opts)
}

// Resolve retrieves the descriptor for the specified artifact by routing the
// request to the appropriate executor based on the artifact's reference.
// It returns the descriptor or an error if no matching executor is found.
func (s *ScopedExecutor) Resolve(ctx context.Context, artifact string) (ocispec.Descriptor, error) {
	executor, err := s.matchExecutor(artifact)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to match executor for artifact %q: %w", artifact, err)
	}
	return executor.Store.Resolve(ctx, artifact)
}

// matchExecutor finds the appropriate executor for the given artifact.
func (s *ScopedExecutor) matchExecutor(artifact string) (*ratify.Executor, error) {
	ref, err := registry.ParseReference(artifact)
	if err != nil {
		return nil, fmt.Errorf("failed to parse artifact reference %q: %w", artifact, err)
	}

	repo := ref.Registry + "/" + ref.Repository
	if executor, ok := s.repository[repo]; ok {
		return executor, nil
	}

	registry := ref.Registry
	if executor, ok := s.registry[registry]; ok {
		return executor, nil
	}

	if _, after, ok := strings.Cut(ref.Registry, "."); ok {
		if executor, ok := s.wildcard[after]; ok {
			return executor, nil
		}
	}
	return nil, fmt.Errorf("no executor configured for the artifact %q", artifact)
}

// registerExecutor registers an executor for a given scope.
func (s *ScopedExecutor) registerExecutor(scope string, executor *ratify.Executor) error {
	if scope == "" {
		return fmt.Errorf("scope cannot be empty")
	}
	if executor == nil {
		return fmt.Errorf("executor cannot be nil")
	}

	if strings.Contains(scope, "/") {
		return s.registerRepository(scope, executor)
	}
	return s.registerRegistry(scope, executor)
}

// registerRepository registers an executor for a specific repository scope.
// The scope must be a valid repository path without wildcards, tags, or digests.
// It returns an error if the scope is invalid or if the executor is nil.
func (s *ScopedExecutor) registerRepository(scope string, executor *ratify.Executor) error {
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

	if s.repository == nil {
		s.repository = map[string]*ratify.Executor{}
	}
	if _, ok := s.repository[scope]; ok {
		return fmt.Errorf("executor already registered for scope %q", scope)
	}
	s.repository[scope] = executor
	return nil
}

// registerRegistry registers an executor for a given registry scope.
// It supports both exact registry matches and wildcard registry matches.
// The scope can be a specific registry (e.g., "registry.example.com") or a
// wildcard registry (e.g., "*.example.com").
func (s *ScopedExecutor) registerRegistry(scope string, executor *ratify.Executor) error {
	ref := registry.Reference{
		Registry: scope,
	}
	if err := ref.ValidateRegistry(); err != nil {
		return fmt.Errorf("invalid scope %q: %w", scope, err)
	}

	switch strings.Count(scope, "*") {
	case 0:
		if s.registry == nil {
			s.registry = map[string]*ratify.Executor{}
		}
		if _, ok := s.registry[scope]; ok {
			return fmt.Errorf("executor already registered for scope %q", scope)
		}
		s.registry[scope] = executor
	case 1:
		if !strings.HasPrefix(scope, "*.") {
			return fmt.Errorf("invalid scope %q: wildcard must be at the beginning of the scope", scope)
		}
		scope = scope[2:]
		if s.wildcard == nil {
			s.wildcard = map[string]*ratify.Executor{}
		}
		if _, ok := s.wildcard[scope]; ok {
			return fmt.Errorf("executor already registered for wildcard scope %q", scope)
		}
		s.wildcard[scope] = executor
	default:
		return fmt.Errorf("invalid scope %q: scope can only contain one wildcard", scope)
	}

	return nil
}
