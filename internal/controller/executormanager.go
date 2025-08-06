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

package controller

import (
	"fmt"
	"sync"
	"sync/atomic"

	configv2alpha1 "github.com/notaryproject/ratify/v2/api/v2alpha1"
	e "github.com/notaryproject/ratify/v2/internal/executor"
	"github.com/notaryproject/ratify/v2/internal/policyenforcer"
	"github.com/notaryproject/ratify/v2/internal/store"
	"github.com/notaryproject/ratify/v2/internal/verifier"
)

// executorManager manages the lifecycle of executor instances across different
// namespaces and names.
type executorManager struct {
	mutex          sync.Mutex
	opts           map[string]e.ScopedOptions
	executor       atomic.Pointer[e.ScopedExecutor]
	maxConcurrency int
}

// GlobalExecutorManager is an instance of executorManager that is used by
// CRD controllers and other components to access the executors.
var GlobalExecutorManager executorManager

func init() {
	GlobalExecutorManager = executorManager{
		opts: make(map[string]e.ScopedOptions),
	}
}

// GetExecutor returns the current executor instance in concurrent safe manner.
// It returns nil if no executor is set.
func (m *executorManager) GetExecutor() *e.ScopedExecutor {
	return m.executor.Load()
}

// SetMaxConcurrency sets the maximum concurrency for the executor manager.
// This should be called before any executors are created.
func (m *executorManager) SetMaxConcurrency(maxConcurrency int) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.maxConcurrency = maxConcurrency
}

// upsertExecutor updates or inserts an executor instance under the given
// namespace and name.
func (m *executorManager) upsertExecutor(namespace, name string, opts *configv2alpha1.Executor) error {
	if opts == nil {
		return fmt.Errorf("executor options cannot be nil")
	}
	m.mutex.Lock()
	defer m.mutex.Unlock()

	scopedOpts, err := convertOptions(opts)
	if err != nil {
		return err
	}

	key := createOptsKey(namespace, name)
	m.opts[key] = scopedOpts

	return m.refreshExecutor()
}

// deleteExecutor removes an executor instance under the given namespace and
// name.
func (m *executorManager) deleteExecutor(namespace, name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	key := createOptsKey(namespace, name)
	if _, exists := m.opts[key]; exists {
		delete(m.opts, key)
		return m.refreshExecutor()
	}
	return fmt.Errorf("executor resource: %s/%s is not found", namespace, name)
}

// refreshExecutor creates a new executor instance based on the current options.
func (m *executorManager) refreshExecutor() error {
	opts := e.Options{
		Executors:      make([]e.ScopedOptions, len(m.opts)),
		MaxConcurrency: m.maxConcurrency,
	}
	i := 0
	for _, scopedOpts := range m.opts {
		opts.Executors[i] = scopedOpts
		i++
	}

	executor, err := e.NewScopedExecutor(opts)
	if err != nil {
		return fmt.Errorf("failed to create executor: %w", err)
	}

	m.executor.Store(executor)
	return nil
}

// convertOptions converts the provided configv2alpha1.Executor options into a
// ScopedOptions.
func convertOptions(opts *configv2alpha1.Executor) (e.ScopedOptions, error) {
	scopedOpts := e.ScopedOptions{
		Scopes: opts.Spec.Scopes,
	}

	verifierOpts, err := convertVerifierOptions(opts.Spec.Verifiers)
	if err != nil {
		return e.ScopedOptions{}, fmt.Errorf("failed to convert verifier options: %w", err)
	}
	scopedOpts.Verifiers = verifierOpts

	storeOpts, err := convertStoreOptions(opts.Spec.Stores)
	if err != nil {
		return e.ScopedOptions{}, fmt.Errorf("failed to convert store options: %w", err)
	}
	scopedOpts.Stores = storeOpts

	scopedOpts.Policy = convertPolicyOptions(opts.Spec.PolicyEnforcer)

	return scopedOpts, nil
}

func convertVerifierOptions(verifiers []*configv2alpha1.VerifierOptions) ([]verifier.NewOptions, error) {
	if verifiers == nil {
		return nil, fmt.Errorf("verifiers cannot be nil")
	}

	verifierOpts := make([]verifier.NewOptions, len(verifiers))
	for i, v := range verifiers {
		verifierOpts[i] = verifier.NewOptions{
			Name:       v.Name,
			Type:       v.Type,
			Parameters: v.Parameters,
		}
	}
	return verifierOpts, nil
}

func convertStoreOptions(stores []*configv2alpha1.StoreOptions) ([]store.NewOptions, error) {
	if stores == nil {
		return nil, fmt.Errorf("stores cannot be nil")
	}

	storeOpts := make([]store.NewOptions, len(stores))
	for i, s := range stores {
		opts := store.NewOptions{
			Type:       s.Type,
			Parameters: s.Parameters,
		}
		storeOpts[i] = opts
	}
	return storeOpts, nil
}

func convertPolicyOptions(policy *configv2alpha1.PolicyEnforcerOptions) *policyenforcer.NewOptions {
	if policy == nil {
		return nil
	}
	return &policyenforcer.NewOptions{
		Type:       policy.Type,
		Parameters: policy.Parameters,
	}
}

func createOptsKey(namespace, name string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}
