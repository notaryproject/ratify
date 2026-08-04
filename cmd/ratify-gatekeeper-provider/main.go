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

package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/notaryproject/ratify/v2/internal/controller"
	"github.com/notaryproject/ratify/v2/internal/httpserver"
	"github.com/notaryproject/ratify/v2/internal/manager"
	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/featureflag"
	"github.com/sirupsen/logrus"
)

var startManagerFunc = manager.StartManager

// main is the entry point for the Ratify server.
func main() {
	common.SetLoggingLevelFromEnv(logrus.StandardLogger())
	featureflag.InitFeatureFlagsFromEnv()
	if err := startRatify(parse()); err != nil {
		logrus.Errorf("Failed to start Ratify: %v", err)
		panic(err)
	}
}

type options struct {
	configFilePath       string
	httpServerAddress    string
	healthServerAddress  string
	certFile             string
	keyFile              string
	gatekeeperCACertFile string
	disableCertRotation  bool
	disableMutation      bool
	disableCRDManager    bool
	verifyTimeout        time.Duration
	mutateTimeout        time.Duration
}

func parse() *options {
	opts := &options{}
	flag.StringVar(&opts.configFilePath, "config", "", "Path to the Ratify configuration file")
	flag.StringVar(&opts.httpServerAddress, "address", "", "HTTP server address")
	flag.StringVar(&opts.healthServerAddress, "health-address", ":9099", "Health check (liveness/readiness) server address")
	flag.StringVar(&opts.certFile, "cert-file", "", "Path to the TLS certificate file")
	flag.StringVar(&opts.keyFile, "key-file", "", "Path to the TLS key file")
	flag.StringVar(&opts.gatekeeperCACertFile, "gatekeeper-ca-cert-file", "", "Path to the Gatekeeper CA certificate file")
	flag.DurationVar(&opts.verifyTimeout, "verify-timeout", 5*time.Second, "Verification timeout duration (e.g. 5s, 1m), default is 5 seconds")
	flag.DurationVar(&opts.mutateTimeout, "mutate-timeout", 2*time.Second, "Mutation timeout duration (e.g. 5s, 1m), default is 2 seconds")
	flag.BoolVar(&opts.disableCertRotation, "disable-cert-rotation", false, "Disable certificate rotation")
	flag.BoolVar(&opts.disableMutation, "disable-mutation", false, "Disable mutation wehbook")
	flag.BoolVar(&opts.disableCRDManager, "disable-crd-manager", false, "Disable CRD manager for Gatekeeper provider")

	flag.Parse()
	logrus.Infof("Starting Ratify with options: %+v", opts)
	return opts
}

func startRatify(opts *options) error {
	if len(opts.httpServerAddress) == 0 {
		return errors.New("HTTP server address is required")
	}
	var certRotatorReady chan struct{}
	if !opts.disableCertRotation {
		certRotatorReady = make(chan struct{})
	}
	serverOpts := &httpserver.ServerOptions{
		HTTPServerAddress:    opts.httpServerAddress,
		CertFile:             opts.certFile,
		KeyFile:              opts.keyFile,
		GatekeeperCACertFile: opts.gatekeeperCACertFile,
		VerifyTimeout:        opts.verifyTimeout,
		MutateTimeout:        opts.mutateTimeout,
		DisableMutation:      opts.disableMutation,
		DisableCRDManager:    opts.disableCRDManager,
		CertRotatorReady:     certRotatorReady,
	}

	// In CRD-manager mode the executor is loaded asynchronously by the
	// reconciler; executorManagerReady is closed once the manager's caches have
	// synced, so readiness no longer blocks once the executor state is known.
	executorManagerReady, executorReady := newExecutorReadiness(serverOpts.DisableCRDManager)
	go startManagerFunc(certRotatorReady, executorManagerReady, serverOpts.DisableMutation, serverOpts.DisableCRDManager)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go runHealthServer(ctx, opts.healthServerAddress, certRotatorReady, executorReady)

	return httpserver.StartServer(serverOpts, opts.configFilePath)
}

// newExecutorReadiness returns the manager-sync signal and the readiness check
// used to gate /readyz in CRD-manager mode. Both are nil when the CRD manager
// is disabled, since the executor is then loaded synchronously at startup.
func newExecutorReadiness(disableCRDManager bool) (chan struct{}, func() bool) {
	if disableCRDManager {
		return nil, nil
	}
	managerSynced := make(chan struct{})
	executorLoaded := func() bool { return controller.GlobalExecutorManager.GetExecutor() != nil }
	return managerSynced, func() bool { return isExecutorReady(executorLoaded, managerSynced) }
}

// isExecutorReady reports whether the CRD-managed executor is loaded, or the
// manager has synced (managerSynced closed) so the pod becomes Ready and fails
// closed even when no valid Executor is installed yet.
func isExecutorReady(executorLoaded func() bool, managerSynced <-chan struct{}) bool {
	if executorLoaded() {
		return true
	}
	select {
	case <-managerSynced:
		return true
	default:
		return false
	}
}

// runHealthServer starts the liveness/readiness health check server. It is a
// no-op when address is empty. It blocks until the context is cancelled.
func runHealthServer(ctx context.Context, address string, certRotatorReady chan struct{}, executorReady func() bool) {
	if address == "" {
		return
	}
	if err := httpserver.StartHealthCheckServer(ctx, httpserver.HealthCheckOptions{
		Address:          address,
		CertRotatorReady: certRotatorReady,
		ExecutorReady:    executorReady,
	}); err != nil {
		logrus.Errorf("health check server stopped with error: %v", err)
	}
}
