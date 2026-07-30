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

// clusterScopeNamespace is the reserved namespace key used to store the
// cluster-scoped executor options. Cluster-scoped Executor resources have an
// empty namespace, so they are grouped under this key and serve as the
// fallback executor when no namespaced executor matches a request.
const clusterScopeNamespace = ""

// executorManager manages the lifecycle of executor instances across different
// namespaces and names.
type executorManager struct {
	mutex sync.Mutex
	// opts maps a namespace to the set of executor options defined in that
	// namespace, keyed by the executor's namespace/name.
	opts map[string]map[string]e.ScopedOptions
	// executors maps a namespace to its compiled ScopedExecutor. The whole map
	// is replaced atomically on every refresh so that GetExecutor stays
	// lock-free.
	executors atomic.Pointer[map[string]*e.ScopedExecutor]
}

// GlobalExecutorManager is an instance of executorManager that is used by
// CRD controllers and other components to access the executors.
var GlobalExecutorManager executorManager

func init() {
	GlobalExecutorManager = executorManager{
		opts: make(map[string]map[string]e.ScopedOptions),
	}
}

// GetExecutor returns the executor responsible for the given namespace in a
// concurrent safe manner. If the namespace has its own executor it is returned,
// otherwise the cluster-scoped executor is returned as a fallback. It returns
// nil if neither is configured.
func (m *executorManager) GetExecutor(namespace string) *e.ScopedExecutor {
	executors := m.executors.Load()
	if executors == nil {
		return nil
	}
	if executor, ok := (*executors)[namespace]; ok {
		return executor
	}
	if executor, ok := (*executors)[clusterScopeNamespace]; ok {
		return executor
	}
	return nil
}

// upsertExecutor updates or inserts an executor instance under the given
// namespace and name.
func (m *executorManager) upsertExecutor(namespace, name string, opts *configv2alpha1.ExecutorSpec) error {
	if opts == nil {
		return fmt.Errorf("executor options cannot be nil")
	}
	m.mutex.Lock()
	defer m.mutex.Unlock()

	scopedOpts, err := convertOptions(opts)
	if err != nil {
		return err
	}

	if m.opts[namespace] == nil {
		m.opts[namespace] = make(map[string]e.ScopedOptions)
	}
	key := createOptsKey(namespace, name)
	m.opts[namespace][key] = scopedOpts

	return m.refreshExecutor(namespace)
}

// deleteExecutor removes an executor instance under the given namespace and
// name.
func (m *executorManager) deleteExecutor(namespace, name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	key := createOptsKey(namespace, name)
	if _, exists := m.opts[namespace][key]; exists {
		delete(m.opts[namespace], key)
		if len(m.opts[namespace]) == 0 {
			delete(m.opts, namespace)
		}
		return m.refreshExecutor(namespace)
	}
	return fmt.Errorf("executor resource: %s/%s is not found", namespace, name)
}

// refreshExecutor rebuilds the ScopedExecutor for a single namespace and
// atomically swaps the executor map. The caller must hold m.mutex.
func (m *executorManager) refreshExecutor(namespace string) error {
	newExecutors := make(map[string]*e.ScopedExecutor)
	if current := m.executors.Load(); current != nil {
		for ns, executor := range *current {
			newExecutors[ns] = executor
		}
	}

	nsOpts := m.opts[namespace]
	if len(nsOpts) == 0 {
		delete(newExecutors, namespace)
		m.executors.Store(&newExecutors)
		return nil
	}

	opts := e.Options{
		Executors: make([]e.ScopedOptions, 0, len(nsOpts)),
	}
	for _, scopedOpts := range nsOpts {
		opts.Executors = append(opts.Executors, scopedOpts)
	}

	executor, err := e.NewScopedExecutor(opts)
	if err != nil {
		return fmt.Errorf("failed to create executor for namespace %q: %w", namespace, err)
	}

	newExecutors[namespace] = executor
	m.executors.Store(&newExecutors)
	return nil
}

// convertOptions converts the provided configv2alpha1.ExecutorSpec options into
// a ScopedOptions.
func convertOptions(opts *configv2alpha1.ExecutorSpec) (e.ScopedOptions, error) {
	scopedOpts := e.ScopedOptions{
		Scopes: opts.Scopes,
	}

	verifierOpts, err := convertVerifierOptions(opts.Verifiers)
	if err != nil {
		return e.ScopedOptions{}, fmt.Errorf("failed to convert verifier options: %w", err)
	}
	scopedOpts.Verifiers = verifierOpts

	storeOpts, err := convertStoreOptions(opts.Stores)
	if err != nil {
		return e.ScopedOptions{}, fmt.Errorf("failed to convert store options: %w", err)
	}
	scopedOpts.Stores = storeOpts

	scopedOpts.Policy = convertPolicyOptions(opts.PolicyEnforcer)
	scopedOpts.Concurrency = opts.Concurrency
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
