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
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
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
	s, err := NewServer("127.0.0.1:0", reg)
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

func TestServer_Start_ShutsDownOnInterrupt(t *testing.T) {
	reg := NewRegistry()
	s, err := NewServer("127.0.0.1:0", reg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start()
	}()

	deadline := time.Now().Add(5 * time.Second)
	for !s.started.Load() {
		if time.Now().After(deadline) {
			t.Fatal("server did not start in time")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("failed to send interrupt: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("expected Start to return nil, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return in time")
	}
}

func TestServer_Run_ListenAndServeError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve port: %v", err)
	}
	defer listener.Close()

	s, err := NewServer(listener.Addr().String(), NewRegistry())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = s.Run(context.Background())
	if err == nil {
		t.Fatal("expected ListenAndServe error")
	}
	if got, want := err.Error(), "failed to start health probe server"; len(got) < len(want) || got[:len(want)] != want {
		t.Fatalf("expected error prefix %q, got %q", want, got)
	}
}

func TestServer_Run_ShutdownError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve port: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("failed to release port: %v", err)
	}

	requestStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	requestErrCh := make(chan error, 1)

	s := &Server{address: address, registry: NewRegistry(), mux: http.NewServeMux()}
	s.mux.HandleFunc("/block", func(w http.ResponseWriter, _ *http.Request) {
		select {
		case <-requestStarted:
		default:
			close(requestStarted)
		}
		<-releaseHandler
		w.WriteHeader(http.StatusOK)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Run(ctx)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not start listening in time")
		}
		time.Sleep(10 * time.Millisecond)
	}

	go func() {
		resp, err := http.Get("http://" + address + "/block")
		if resp != nil {
			_ = resp.Body.Close()
		}
		requestErrCh <- err
	}()

	select {
	case <-requestStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("blocking request did not reach handler")
	}

	cancel()

	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "failed to shutdown health probe server") {
			t.Fatalf("expected shutdown error, got %v", err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("Run did not return shutdown error in time")
	}

	close(releaseHandler)

	select {
	case err := <-requestErrCh:
		if err != nil {
			t.Fatalf("blocking request failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocking request did not complete in time")
	}
}

func TestServer_Run_InvalidState(t *testing.T) {
	tests := []struct {
		name    string
		server  *Server
		ctx     context.Context
		wantErr string
	}{
		{
			name:    "nil server",
			server:  nil,
			ctx:     context.Background(),
			wantErr: "health probe server is nil",
		},
		{
			name:    "nil context",
			server:  &Server{address: ":0", mux: http.NewServeMux(), registry: NewRegistry()},
			ctx:     nil,
			wantErr: "health probe context is nil",
		},
		{
			name:    "nil mux",
			server:  &Server{address: ":0", registry: NewRegistry()},
			ctx:     context.Background(),
			wantErr: "health probe mux is nil",
		},
		{
			name:    "nil registry",
			server:  &Server{address: ":0", mux: http.NewServeMux()},
			ctx:     context.Background(),
			wantErr: "health probe registry is nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.server.Run(tt.ctx)
			if err == nil || err.Error() != tt.wantErr {
				t.Fatalf("expected error %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestEvaluate_NilChecker(t *testing.T) {
	results, healthy := evaluate([]HealthChecker{nil})
	if healthy {
		t.Fatal("expected evaluate to report unhealthy for nil checker")
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Name != "unknown" {
		t.Fatalf("expected checker name %q, got %q", "unknown", results[0].Name)
	}
	if results[0].Status != statusError {
		t.Fatalf("expected checker status %q, got %q", statusError, results[0].Status)
	}
	if results[0].Error != msgCheckerNil {
		t.Fatalf("expected checker error %q, got %q", msgCheckerNil, results[0].Error)
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

func TestReadyz_NotStarted(t *testing.T) {
	tests := []struct {
		name   string
		server *Server
	}{
		{
			name:   "nil server",
			server: nil,
		},
		{
			name:   "server not started",
			server: &Server{registry: NewRegistry()},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tt.server.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("expected 503 when ready server is unavailable, got %d", rec.Code)
			}

			var resp response
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}
			if resp.Status != statusNotReady {
				t.Fatalf("expected status %q, got %q", statusNotReady, resp.Status)
			}
		})
	}
}

func TestServer_RegisterHandlers(t *testing.T) {
	s, err := NewServer(":9090", NewRegistry())
	if err != nil {
		t.Fatalf("unexpected error creating server: %v", err)
	}

	tests := []struct {
		path       string
		wantStatus string
	}{
		{path: "/healthz", wantStatus: statusNotAlive},
		{path: "/readyz", wantStatus: statusNotReady},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))

			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("expected %s to be registered and return 503, got %d", tt.path, rec.Code)
			}

			var resp response
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}
			if resp.Status != tt.wantStatus {
				t.Fatalf("expected status %q, got %q", tt.wantStatus, resp.Status)
			}
		})
	}
}

func TestServer_RegisterHandlers_NilGuards(t *testing.T) {
	tests := []struct {
		name string
		run  func()
	}{
		{
			name: "nil server",
			run: func() {
				var s *Server
				s.registerHandlers()
			},
		},
		{
			name: "nil mux",
			run: func() {
				s := &Server{registry: NewRegistry()}
				s.registerHandlers()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("registerHandlers panicked: %v", r)
				}
			}()
			tt.run()
		})
	}
}
