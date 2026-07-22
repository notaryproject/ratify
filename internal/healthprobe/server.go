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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	readHeaderTimeout = 5 * time.Second
	shutdownTimeout   = 5 * time.Second

	statusNotAlive = "not alive"
	statusNotReady = "not ready"
	statusError    = "error"
	msgCheckerNil  = "checker is nil"
)

// CheckResult captures the outcome of a single health check.
type CheckResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type response struct {
	Status string        `json:"status"`
	Checks []CheckResult `json:"checks,omitempty"`
}

// Server serves plain HTTP /healthz and /readyz endpoints on a dedicated port.
type Server struct {
	address  string
	registry *Registry
	mux      *http.ServeMux
	started  atomic.Bool
}

// NewServer creates a dedicated health probe server.
func NewServer(address string, registry *Registry) (*Server, error) {
	if address == "" {
		return nil, fmt.Errorf("health probe address is required")
	}
	if registry == nil {
		registry = NewRegistry()
	}

	s := &Server{
		address:  address,
		registry: registry,
		mux:      http.NewServeMux(),
	}
	s.registerHandlers()
	return s, nil
}

func (s *Server) registerHandlers() {
	if s == nil || s.mux == nil {
		return
	}

	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.HandleFunc("/readyz", s.handleReadyz)
}

// Start runs the health probe server until SIGINT or SIGTERM is received.
func (s *Server) Start() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return s.Run(ctx)
}

// Run runs the health probe server until the context is canceled.
func (s *Server) Run(ctx context.Context) error {
	if s == nil {
		return fmt.Errorf("health probe server is nil")
	}
	if ctx == nil {
		return fmt.Errorf("health probe context is nil")
	}
	if s.mux == nil {
		return fmt.Errorf("health probe mux is nil")
	}
	if s.registry == nil {
		return fmt.Errorf("health probe registry is nil")
	}

	srv := &http.Server{
		Addr:              s.address,
		Handler:           s.mux,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	s.started.Store(true)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("failed to start health probe server: %w", err)
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("failed to shutdown health probe server: %w", err)
		}
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	if s == nil || !s.started.Load() || s.registry == nil {
		writeJSON(w, http.StatusServiceUnavailable, response{Status: statusNotAlive})
		return
	}

	results, healthy := evaluate(s.registry.LivenessCheckers())
	if !healthy {
		writeJSON(w, http.StatusServiceUnavailable, response{Status: statusNotAlive, Checks: results})
		return
	}

	writeJSON(w, http.StatusOK, response{Status: "ok", Checks: results})
}

func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if s == nil || !s.started.Load() || s.registry == nil {
		writeJSON(w, http.StatusServiceUnavailable, response{Status: statusNotReady})
		return
	}

	checkers := s.registry.ReadinessCheckers()
	if len(checkers) == 0 {
		writeJSON(w, http.StatusServiceUnavailable, response{Status: statusNotReady, Checks: []CheckResult{{
			Name:   "registry",
			Status: statusError,
			Error:  "no readiness checks registered",
		}}})
		return
	}

	results, healthy := evaluate(checkers)
	if !healthy {
		writeJSON(w, http.StatusServiceUnavailable, response{Status: statusNotReady, Checks: results})
		return
	}

	writeJSON(w, http.StatusOK, response{Status: "ok", Checks: results})
}

func evaluate(checkers []HealthChecker) ([]CheckResult, bool) {
	results := make([]CheckResult, 0, len(checkers))
	healthy := true

	for _, checker := range checkers {
		if checker == nil {
			healthy = false
			results = append(results, CheckResult{
				Name:   "unknown",
				Status: statusError,
				Error:  msgCheckerNil,
			})
			continue
		}

		if err := checker.Check(); err != nil {
			healthy = false
			results = append(results, CheckResult{
				Name:   checker.Name(),
				Status: statusError,
				Error:  err.Error(),
			})
			continue
		}

		results = append(results, CheckResult{
			Name:   checker.Name(),
			Status: "ok",
		})
	}

	return results, healthy
}

func writeJSON(w http.ResponseWriter, statusCode int, payload response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}
