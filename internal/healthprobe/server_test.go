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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestServer(t *testing.T, registry *Registry) *Server {
	t.Helper()
	s, err := NewServer(":9090", registry)
	if err != nil {
		t.Fatalf("unexpected error creating server: %v", err)
	}
	s.started.Store(true)
	return s
}

func TestNewServer_EmptyAddress(t *testing.T) {
	_, err := NewServer("", nil)
	if err == nil || err.Error() != "health probe address is required" {
		t.Fatalf("expected address error, got %v", err)
	}
}

func TestNewServer_NilRegistry(t *testing.T) {
	s, err := NewServer(":9090", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.registry == nil {
		t.Fatal("expected non-nil registry when nil is passed")
	}
}

func TestHealthz_AllPass(t *testing.T) {
	reg := NewRegistry()
	_ = reg.RegisterLiveness(MustNewChecker("check1", func() error { return nil }))
	_ = reg.RegisterLiveness(MustNewChecker("check2", func() error { return nil }))

	s := newTestServer(t, reg)
	rec := httptest.NewRecorder()
	s.handleHealthz(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp response
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status != "ok" {
		t.Fatalf("expected status 'ok', got %q", resp.Status)
	}
	if len(resp.Checks) != 2 {
		t.Fatalf("expected 2 checks, got %d", len(resp.Checks))
	}
	for _, c := range resp.Checks {
		if c.Status != "ok" {
			t.Fatalf("expected check status 'ok', got %q", c.Status)
		}
	}
}

func TestHealthz_OneFails(t *testing.T) {
	reg := NewRegistry()
	_ = reg.RegisterLiveness(MustNewChecker("ok-check", func() error { return nil }))
	_ = reg.RegisterLiveness(MustNewChecker("bad-check", func() error { return errors.New("disk full") }))

	s := newTestServer(t, reg)
	rec := httptest.NewRecorder()
	s.handleHealthz(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}

	var resp response
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Status != "not alive" {
		t.Fatalf("expected status 'not alive', got %q", resp.Status)
	}

	found := false
	for _, c := range resp.Checks {
		if c.Name == "bad-check" {
			found = true
			if c.Status != "error" {
				t.Fatalf("expected check status 'error', got %q", c.Status)
			}
			if c.Error != "disk full" {
				t.Fatalf("expected error 'disk full', got %q", c.Error)
			}
		}
	}
	if !found {
		t.Fatal("expected 'bad-check' in response")
	}
}

func TestHealthz_NoCheckers(t *testing.T) {
	reg := NewRegistry()
	s := newTestServer(t, reg)
	rec := httptest.NewRecorder()
	s.handleHealthz(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with no liveness checks, got %d", rec.Code)
	}
}

func TestReadyz_AllPass(t *testing.T) {
	reg := NewRegistry()
	_ = reg.RegisterReadiness(MustNewChecker("ready1", func() error { return nil }))

	s := newTestServer(t, reg)
	rec := httptest.NewRecorder()
	s.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp response
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Status != "ok" {
		t.Fatalf("expected status 'ok', got %q", resp.Status)
	}
}

func TestReadyz_NoCheckers(t *testing.T) {
	reg := NewRegistry()
	s := newTestServer(t, reg)
	rec := httptest.NewRecorder()
	s.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when no readiness checks registered, got %d", rec.Code)
	}
}

func TestReadyz_OneFails(t *testing.T) {
	reg := NewRegistry()
	_ = reg.RegisterReadiness(MustNewChecker("db", func() error { return errors.New("connection refused") }))

	s := newTestServer(t, reg)
	rec := httptest.NewRecorder()
	s.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}

	var resp response
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Status != "not ready" {
		t.Fatalf("expected status 'not ready', got %q", resp.Status)
	}
	if len(resp.Checks) == 0 {
		t.Fatal("expected checks in response")
	}
	if resp.Checks[0].Error != "connection refused" {
		t.Fatalf("expected error 'connection refused', got %q", resp.Checks[0].Error)
	}
}

func TestServer_ResponseContentType(t *testing.T) {
	reg := NewRegistry()
	s := newTestServer(t, reg)
	rec := httptest.NewRecorder()
	s.handleHealthz(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected Content-Type 'application/json', got %q", ct)
	}
}

func TestServer_Run_CancelContext(t *testing.T) {
	reg := NewRegistry()
	s, err := NewServer(":0", reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Run(ctx)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("unexpected error from Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}

func TestServer_NotStarted(t *testing.T) {
	reg := NewRegistry()
	s, _ := NewServer(":9090", reg)
	// Don't set started to true
	rec := httptest.NewRecorder()
	s.handleHealthz(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when server not started, got %d", rec.Code)
	}
}
