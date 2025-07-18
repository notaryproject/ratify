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
	"errors"
	"flag"
	"time"

	"github.com/notaryproject/ratify/v2/internal/httpserver"
	"github.com/notaryproject/ratify/v2/internal/manager"
	_ "github.com/notaryproject/ratify/v2/internal/policyenforcer/threshold"  // Register policy enforcers
	_ "github.com/notaryproject/ratify/v2/internal/verifier/factory/cosign"   // Register the Cosign verifier
	_ "github.com/notaryproject/ratify/v2/internal/verifier/factory/notation" // Register the Notation verifier
	"github.com/sirupsen/logrus"
)

var startManagerFunc = manager.StartManager

// main is the entry point for the Ratify server.
func main() {
	if err := startRatify(parse()); err != nil {
		logrus.Errorf("Failed to start Ratify: %v", err)
		panic(err)
	}
}

type options struct {
	configFilePath       string
	httpServerAddress    string
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

	go startManagerFunc(certRotatorReady, serverOpts.DisableMutation, serverOpts.DisableCRDManager)
	return httpserver.StartServer(serverOpts, opts.configFilePath)
}
