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
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStartHealthCheckServer_RequiresAddress(t *testing.T) {
	if err := StartHealthCheckServer(context.Background(), HealthCheckOptions{}); err == nil {
		t.Fatal("expected error when Address is empty, got nil")
	}
}

func TestStartHealthCheckServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve a port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- StartHealthCheckServer(ctx, HealthCheckOptions{Address: addr})
	}()

	base := "http://" + addr
	waitForServer(t, base+livenessPath)

	for _, path := range []string{livenessPath, readinessPath} {
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: got status %d, want %d", path, resp.StatusCode, http.StatusOK)
		}
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("StartHealthCheckServer returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not shut down after context cancel")
	}
}

// waitForServer polls url until it responds or the timeout elapses.
func waitForServer(t *testing.T, url string) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		select {
		case <-deadline:
			t.Fatalf("server did not start listening at %s", url)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestNewReadinessTracker(t *testing.T) {
	t.Run("nil channel is ready immediately", func(t *testing.T) {
		isReady := newReadinessTracker(nil)
		if !isReady() {
			t.Fatal("expected ready when cert rotation is disabled")
		}
	})

	t.Run("flips to ready when channel closes", func(t *testing.T) {
		ch := make(chan struct{})
		isReady := newReadinessTracker(ch)
		if isReady() {
			t.Fatal("expected not ready before channel closes")
		}

		close(ch)

		deadline := time.After(2 * time.Second)
		for {
			if isReady() {
				return
			}
			select {
			case <-deadline:
				t.Fatal("expected ready after channel closed")
			default:
				time.Sleep(5 * time.Millisecond)
			}
		}
	})
}

func TestHealthHandler(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		ready      bool
		wantStatus int
	}{
		{name: "liveness is always ok when not ready", path: livenessPath, ready: false, wantStatus: http.StatusOK},
		{name: "liveness is always ok when ready", path: livenessPath, ready: true, wantStatus: http.StatusOK},
		{name: "readiness is unavailable when not ready", path: readinessPath, ready: false, wantStatus: http.StatusServiceUnavailable},
		{name: "readiness is ok when ready", path: readinessPath, ready: true, wantStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := healthHandler(func() bool { return tt.ready })
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("GET %s ready=%v: got status %d, want %d", tt.path, tt.ready, rec.Code, tt.wantStatus)
			}
		})
	}
}
