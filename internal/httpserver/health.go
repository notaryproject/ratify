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
	"sync/atomic"
)

// healthStatus tracks whether the server is ready to serve traffic.
type healthStatus struct {
	alive atomic.Bool
	ready atomic.Bool
}

type healthResponse struct {
	Status string `json:"status"`
}

// healthzHandler returns 200 if the process is alive, 503 otherwise.
// This is the Kubernetes liveness probe endpoint.
func (s *server) healthzHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !s.health.alive.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(healthResponse{Status: "not alive"}) //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(healthResponse{Status: "ok"}) //nolint:errcheck
	}
}

// readyzHandler returns 200 if the server has a valid executor configured
// and is ready to handle verification requests.
func (s *server) readyzHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !s.health.ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(healthResponse{Status: "not ready"}) //nolint:errcheck
			return
		}
		if s.getExecutor() == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(healthResponse{Status: "no executor configured"}) //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(healthResponse{Status: "ok"}) //nolint:errcheck
	}
}
