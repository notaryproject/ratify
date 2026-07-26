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
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// executorManager manages the lifecycle of executor instances across different
// namespaces and names.
type executorManager struct {
	mutex sync.Mutex
	opts  map[string]e.ScopedOptions
	// generations records the last successfully applied metadata.generation
	// per resource, used to tell a real spec change apart from a re-reconcile
	// of an unchanged spec.
	generations map[string]int64
	executor    atomic.Pointer[e.ScopedExecutor]
}

// GlobalExecutorManager is an instance of executorManager that is used by
// CRD controllers and other components to access the executors.
var GlobalExecutorManager executorManager

func init() {
	GlobalExecutorManager = executorManager{
		opts:        make(map[string]e.ScopedOptions),
		generations: make(map[string]int64),
	}
}

// GetExecutor returns the current executor instance in concurrent safe manner.
// It returns nil if no executor is set.
func (m *executorManager) GetExecutor() *e.ScopedExecutor {
	return m.executor.Load()
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
	prevOpts, existed := m.opts[key]
	prevGen, genTracked := m.generations[key]
	newGen := opts.GetGeneration()
	m.opts[key] = scopedOpts

	if err := m.refreshExecutor(); err != nil {
		// Roll back the desired-state map so that a single broken config does
		// not pollute m.opts and block subsequent reconciles of other
		// (valid, unrelated) Executor resources.
		if existed {
			m.opts[key] = prevOpts
		} else {
			delete(m.opts, key)
		}

		// If a previously built executor is still being served, the data plane
		// keeps enforcing the last-known-good config. Warn loudly only when the
		// spec actually changed (metadata.generation advanced): that is an
		// operator edit that is silently NOT enforced until the config is fixed
		// or the provider is restarted. An unchanged generation means a
		// transient failure (e.g. a dependency such as Azure Key Vault was
		// briefly unreachable) on a re-reconcile of the same spec, where
		// retaining the cached executor is the intended graceful degradation.
		if m.executor.Load() != nil {
			specChanged := !genTracked || prevGen != newGen
			if specChanged {
				logf.Log.Error(err, "Executor configuration changed but failed to build; retaining the last-known-good executor. The updated configuration is NOT enforced on the data plane until the invalid config is corrected or the provider is restarted", "executor", key, "generation", newGen)
			} else {
				logf.Log.Info("Failed to rebuild Executor from an unchanged configuration (likely a transient error); retaining the last-known-good executor", "executor", key, "generation", newGen)
			}
		}
		return err
	}

	if m.generations == nil {
		m.generations = make(map[string]int64)
	}
	m.generations[key] = newGen
	return nil
}

// deleteExecutor removes an executor instance under the given namespace and
// name.
func (m *executorManager) deleteExecutor(namespace, name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	key := createOptsKey(namespace, name)
	if _, exists := m.opts[key]; exists {
		delete(m.opts, key)
		delete(m.generations, key)
		return m.refreshExecutor()
	}
	return fmt.Errorf("executor resource: %s/%s is not found", namespace, name)
}

// refreshExecutor creates a new executor instance based on the current options.
func (m *executorManager) refreshExecutor() error {
	opts := e.Options{
		Executors: make([]e.ScopedOptions, len(m.opts)),
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
	scopedOpts.Concurrency = opts.Spec.Concurrency
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
