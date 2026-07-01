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

package manager

import (
	"fmt"
	"sync"

	"github.com/notaryproject/ratify/v2/internal/healthprobe"
)

const managerCheckerName = "controller-runtime-manager"

// ReadySignal tracks when the controller-runtime manager has started.
type ReadySignal struct {
	once  sync.Once
	ready chan struct{}
}

// NewReadySignal creates a manager readiness signal.
func NewReadySignal() *ReadySignal {
	return &ReadySignal{
		ready: make(chan struct{}),
	}
}

// Done returns a channel that closes once the manager is ready.
func (r *ReadySignal) Done() <-chan struct{} {
	if r == nil {
		return nil
	}
	return r.ready
}

// MarkReady closes the readiness signal once.
func (r *ReadySignal) MarkReady() {
	if r == nil || r.ready == nil {
		return
	}

	r.once.Do(func() {
		close(r.ready)
	})
}

// IsReady reports whether the manager readiness signal has fired.
func (r *ReadySignal) IsReady() bool {
	if r == nil || r.ready == nil {
		return false
	}

	select {
	case <-r.ready:
		return true
	default:
		return false
	}
}

// Checker returns a readiness check for the controller-runtime manager.
func (r *ReadySignal) Checker() healthprobe.HealthChecker {
	return healthprobe.MustNewChecker(managerCheckerName, func() error {
		if r == nil {
			return fmt.Errorf("manager readiness signal is nil")
		}
		if !r.IsReady() {
			return fmt.Errorf("controller-runtime manager is not ready")
		}
		return nil
	})
}
