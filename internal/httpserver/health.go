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
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// livenessPath is the endpoint used by the Kubernetes liveness probe.
	livenessPath = "/healthz"
	// readinessPath is the endpoint used by the Kubernetes readiness probe.
	readinessPath = "/readyz"
	// shutdownTimeout is the maximum duration to wait for the health check
	// server to shut down gracefully.
	shutdownTimeout = 5 * time.Second
)

// HealthCheckOptions holds the configuration for the health check server.
type HealthCheckOptions struct {
	// Address is the address where the health check server listens for
	// liveness and readiness probes. It should be in the format "host:port"
	// (e.g., ":9099").
	// Required.
	Address string

	// CertRotatorReady is closed when TLS certificate rotation has completed.
	// While it is open, the readiness probe reports not ready so that
	// Gatekeeper does not route verification traffic to a pod that cannot yet
	// serve TLS. If nil, cert rotation is disabled and the pod is considered
	// ready as soon as the health check server starts.
	// Optional.
	CertRotatorReady chan struct{}
}

// StartHealthCheckServer starts a plaintext HTTP server that exposes the
// liveness (/healthz) and readiness (/readyz) probe endpoints. The server uses
// plaintext HTTP (no mTLS) because the kubelet performing the probes cannot
// present a client certificate. It blocks until the server stops.
func StartHealthCheckServer(opts HealthCheckOptions) error {
	var ready atomic.Bool
	if opts.CertRotatorReady == nil {
		// Cert rotation is disabled: the pod is ready as soon as it starts.
		ready.Store(true)
	} else {
		go func() {
			<-opts.CertRotatorReady
			ready.Store(true)
			logrus.Info("readiness probe: TLS cert rotator is ready")
		}()
	}

	mux := http.NewServeMux()
	mux.HandleFunc(livenessPath, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc(readinessPath, func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:         opts.Address,
		Handler:      mux,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
		<-quit

		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			logrus.Errorf("failed to shutdown health check server: %v", err)
		}
	}()

	logrus.Infof("starting health check server at %s", opts.Address)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
