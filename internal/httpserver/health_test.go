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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStartHealthCheckServer_RequiresAddress(t *testing.T) {
	if err := StartHealthCheckServer(HealthCheckOptions{}); err == nil {
		t.Fatal("expected error when Address is empty, got nil")
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
