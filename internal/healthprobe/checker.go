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

package healthprobe

import (
	"errors"
	"fmt"
	"sync"
)

// HealthChecker reports component health to the dedicated health probe server.
type HealthChecker interface {
	Name() string
	Check() error
}

// CheckerFunc adapts a function into a named health checker.
type CheckerFunc struct {
	name string
	fn   func() error
}

// NewChecker creates a named health checker.
func NewChecker(name string, fn func() error) (*CheckerFunc, error) {
	if name == "" {
		return nil, errors.New("checker name is required")
	}
	if fn == nil {
		return nil, errors.New("checker function is required")
	}
	return &CheckerFunc{name: name, fn: fn}, nil
}

// MustNewChecker creates a checker and panics if the checker is invalid.
func MustNewChecker(name string, fn func() error) *CheckerFunc {
	checker, err := NewChecker(name, fn)
	if err != nil {
		panic(err)
	}
	return checker
}

// Name returns the checker name.
func (c *CheckerFunc) Name() string {
	if c == nil {
		return ""
	}
	return c.name
}

// Check runs the checker function.
func (c *CheckerFunc) Check() error {
	if c == nil {
		return errors.New("checker is nil")
	}
	if c.fn == nil {
		return errors.New("checker function is nil")
	}
	return c.fn()
}

// Registry stores liveness and readiness checks for the health probe server.
type Registry struct {
	mu        sync.RWMutex
	liveness  []HealthChecker
	readiness []HealthChecker
}

// NewRegistry creates an empty checker registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// RegisterLiveness adds a liveness checker.
func (r *Registry) RegisterLiveness(checker HealthChecker) error {
	return r.register(&r.liveness, checker)
}

// RegisterReadiness adds a readiness checker.
func (r *Registry) RegisterReadiness(checker HealthChecker) error {
	return r.register(&r.readiness, checker)
}

func (r *Registry) register(target *[]HealthChecker, checker HealthChecker) error {
	if r == nil {
		return errors.New("registry is nil")
	}
	if checker == nil {
		return errors.New("checker is nil")
	}
	if checker.Name() == "" {
		return errors.New("checker name is required")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, existing := range *target {
		if existing.Name() == checker.Name() {
			return fmt.Errorf("checker %q is already registered", checker.Name())
		}
	}

	*target = append(*target, checker)
	return nil
}

// LivenessCheckers returns a snapshot of the registered liveness checks.
func (r *Registry) LivenessCheckers() []HealthChecker {
	if r == nil {
		return nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	return append([]HealthChecker(nil), r.liveness...)
}

// ReadinessCheckers returns a snapshot of the registered readiness checks.
func (r *Registry) ReadinessCheckers() []HealthChecker {
	if r == nil {
		return nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	return append([]HealthChecker(nil), r.readiness...)
}
