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

package httpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/notaryproject/ratify/v2/internal/executor"
	"github.com/notaryproject/ratify/v2/internal/healthprobe"
)

const (
	httpServerAliveCheckerName    = "http-server-alive"
	httpServerExecutorCheckerName = "http-server-executor"
)

// HealthStatus tracks whether the main Ratify HTTP server is serving traffic.
type HealthStatus struct {
	alive atomic.Bool
	ready atomic.Bool
}

// healthStatus preserves compatibility with existing package-local tests.
type healthStatus = HealthStatus

type healthResponse struct {
	Status string `json:"status"`
}

// NewHealthStatus creates a server health tracker.
func NewHealthStatus() *HealthStatus {
	return &HealthStatus{}
}

// MarkAlive records that the main Ratify HTTP server is ready to accept traffic.
func (h *HealthStatus) MarkAlive() {
	if h == nil {
		return
	}
	h.alive.Store(true)
}

// MarkReady records that the main Ratify HTTP server has a usable executor.
func (h *HealthStatus) MarkReady() {
	if h == nil {
		return
	}
	h.ready.Store(true)
}

// IsAlive reports whether the main Ratify HTTP server is serving traffic.
func (h *HealthStatus) IsAlive() bool {
	if h == nil {
		return false
	}
	return h.alive.Load()
}

// IsReady reports whether the main Ratify HTTP server has a usable executor.
func (h *HealthStatus) IsReady() bool {
	if h == nil {
		return false
	}
	return h.ready.Load()
}

// AliveChecker returns a liveness check for the main Ratify HTTP server.
func (h *HealthStatus) AliveChecker() healthprobe.HealthChecker {
	return healthprobe.MustNewChecker(httpServerAliveCheckerName, func() error {
		if h == nil {
			return fmt.Errorf("http server health status is nil")
		}
		if !h.IsAlive() {
			return fmt.Errorf("http server is not serving")
		}
		return nil
	})
}

// ExecutorChecker returns a readiness check for the executor backing the HTTP server.
func (h *HealthStatus) ExecutorChecker(getExecutor func() *executor.ScopedExecutor) healthprobe.HealthChecker {
	return healthprobe.MustNewChecker(httpServerExecutorCheckerName, func() error {
		if h == nil {
			return fmt.Errorf("http server health status is nil")
		}
		if !h.IsAlive() {
			return fmt.Errorf("http server is not serving")
		}
		if getExecutor == nil {
			return fmt.Errorf("executor getter is nil")
		}
		if getExecutor() == nil {
			return fmt.Errorf("executor is not loaded")
		}
		return nil
	})
}

func (s *server) healthzHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if s == nil || s.health == nil || !s.health.IsAlive() {
			writeHealthResponse(w, http.StatusServiceUnavailable, healthResponse{Status: "not alive"})
			return
		}
		writeHealthResponse(w, http.StatusOK, healthResponse{Status: "ok"})
	}
}

func (s *server) readyzHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if s == nil || s.health == nil || !s.health.IsAlive() || !s.health.IsReady() {
			writeHealthResponse(w, http.StatusServiceUnavailable, healthResponse{Status: "not ready"})
			return
		}
		if s.getExecutor == nil || s.getExecutor() == nil {
			writeHealthResponse(w, http.StatusServiceUnavailable, healthResponse{Status: "no executor configured"})
			return
		}
		writeHealthResponse(w, http.StatusOK, healthResponse{Status: "ok"})
	}
}

func writeHealthResponse(w http.ResponseWriter, statusCode int, payload healthResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}
