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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/notaryproject/ratify/v2/internal/executor"
)

func TestHealthzHandler_Alive(t *testing.T) {
	s := &server{
		health: &healthStatus{},
	}
	s.health.alive.Store(true)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	s.healthzHandler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	var resp healthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", resp.Status)
	}
}

func TestHealthzHandler_NotAlive(t *testing.T) {
	s := &server{
		health: &healthStatus{},
	}
	// alive defaults to false

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	s.healthzHandler().ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", w.Code)
	}
	var resp healthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status != "not alive" {
		t.Errorf("expected status 'not alive', got %q", resp.Status)
	}
}

func TestReadyzHandler_NotReady(t *testing.T) {
	s := &server{
		health: &healthStatus{},
	}
	s.health.alive.Store(true)
	// ready defaults to false

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	s.readyzHandler().ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", w.Code)
	}
}

func TestReadyzHandler_NoExecutor(t *testing.T) {
	s := &server{
		health:      &healthStatus{},
		getExecutor: func() *executor.ScopedExecutor { return nil },
	}
	s.health.alive.Store(true)
	s.health.ready.Store(true)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	s.readyzHandler().ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", w.Code)
	}
	var resp healthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status != "no executor configured" {
		t.Errorf("expected 'no executor configured', got %q", resp.Status)
	}
}

func TestReadyzHandler_Ready(t *testing.T) {
	s := &server{
		health:      &healthStatus{},
		getExecutor: func() *executor.ScopedExecutor { return &executor.ScopedExecutor{} },
	}
	s.health.alive.Store(true)
	s.health.ready.Store(true)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	s.readyzHandler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	var resp healthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", resp.Status)
	}
}

func TestReadyzHandler_NilGetExecutor(t *testing.T) {
	s := &server{
		health:      &healthStatus{},
		getExecutor: nil,
	}
	s.health.alive.Store(true)
	s.health.ready.Store(true)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	s.readyzHandler().ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", w.Code)
	}
}

func TestMarkAlive_NilReceiver(t *testing.T) {
	var h *HealthStatus
	h.MarkAlive() // should not panic
}

func TestMarkAlive(t *testing.T) {
	h := NewHealthStatus()
	if h.IsAlive() {
		t.Error("expected not alive initially")
	}
	h.MarkAlive()
	if !h.IsAlive() {
		t.Error("expected alive after MarkAlive")
	}
}

func TestMarkReady_NilReceiver(t *testing.T) {
	var h *HealthStatus
	h.MarkReady() // should not panic
}

func TestMarkReady(t *testing.T) {
	h := NewHealthStatus()
	if h.IsReady() {
		t.Error("expected not ready initially")
	}
	h.MarkReady()
	if !h.IsReady() {
		t.Error("expected ready after MarkReady")
	}
}

func TestIsAlive_NilReceiver(t *testing.T) {
	var h *HealthStatus
	if h.IsAlive() {
		t.Error("expected false for nil receiver")
	}
}

func TestIsReady_NilReceiver(t *testing.T) {
	var h *HealthStatus
	if h.IsReady() {
		t.Error("expected false for nil receiver")
	}
}

func TestAliveChecker_NilReceiver(t *testing.T) {
	var h *HealthStatus
	checker := h.AliveChecker()
	if err := checker.Check(); err == nil {
		t.Error("expected error for nil health status")
	}
}

func TestAliveChecker_NotAlive(t *testing.T) {
	h := NewHealthStatus()
	checker := h.AliveChecker()
	if checker.Name() != httpServerAliveCheckerName {
		t.Errorf("unexpected checker name: %s", checker.Name())
	}
	if err := checker.Check(); err == nil {
		t.Error("expected error when not alive")
	}
}

func TestAliveChecker_Alive(t *testing.T) {
	h := NewHealthStatus()
	h.MarkAlive()
	checker := h.AliveChecker()
	if err := checker.Check(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExecutorChecker_NilReceiver(t *testing.T) {
	var h *HealthStatus
	checker := h.ExecutorChecker(func() *executor.ScopedExecutor { return &executor.ScopedExecutor{} })
	if err := checker.Check(); err == nil {
		t.Error("expected error for nil health status")
	}
}

func TestExecutorChecker_NotAlive(t *testing.T) {
	h := NewHealthStatus()
	checker := h.ExecutorChecker(func() *executor.ScopedExecutor { return &executor.ScopedExecutor{} })
	if err := checker.Check(); err == nil {
		t.Error("expected error when not alive")
	}
}

func TestExecutorChecker_NilGetter(t *testing.T) {
	h := NewHealthStatus()
	h.MarkAlive()
	checker := h.ExecutorChecker(nil)
	if err := checker.Check(); err == nil {
		t.Error("expected error when getter is nil")
	}
}

func TestExecutorChecker_NilExecutor(t *testing.T) {
	h := NewHealthStatus()
	h.MarkAlive()
	checker := h.ExecutorChecker(func() *executor.ScopedExecutor { return nil })
	if err := checker.Check(); err == nil {
		t.Error("expected error when executor is nil")
	}
}

func TestExecutorChecker_Success(t *testing.T) {
	h := NewHealthStatus()
	h.MarkAlive()
	checker := h.ExecutorChecker(func() *executor.ScopedExecutor { return &executor.ScopedExecutor{} })
	if err := checker.Check(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
