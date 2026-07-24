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
	"flag"
	"net"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestMain_FailedStartingRatify(t *testing.T) {
	args := []string{
		"-config=config.json",
		"-cert-file=cert.pem",
		"-key-file=key.pem",
		"-verify-timeout=10s",
	}
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()
	os.Args = append([]string{"cmd"}, args...)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic, but got none")
		}
	}()
	main()
}

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected *options
	}{
		{
			name: "all options set",
			args: []string{
				"-config=config.json",
				"-address=:8080",
				"-cert-file=cert.pem",
				"-key-file=key.pem",
				"-verify-timeout=10s",
				"-leader-elect",
			},
			expected: &options{
				configFilePath:       "config.json",
				httpServerAddress:    ":8080",
				healthServerAddress:  ":9099",
				certFile:             "cert.pem",
				keyFile:              "key.pem",
				enableLeaderElection: true,
				verifyTimeout:        10 * time.Second,
				mutateTimeout:        2 * time.Second,
			},
		},
		{
			name: "only timeout provided",
			args: []string{
				"-verify-timeout=30s",
				"-mutate-timeout=10s",
			},
			expected: &options{
				healthServerAddress: ":9099",
				verifyTimeout:       30 * time.Second,
				mutateTimeout:       10 * time.Second,
			},
		},
		{
			name: "default values",
			args: []string{},
			expected: &options{
				healthServerAddress: ":9099",
				verifyTimeout:       5 * time.Second,
				mutateTimeout:       2 * time.Second,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and reset original command-line args and flags
			oldArgs := os.Args
			os.Args = append([]string{"cmd"}, tt.args...)
			flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

			opts := parse()
			if !reflect.DeepEqual(opts, tt.expected) {
				t.Errorf("parse() = %+v, want %+v", opts, tt.expected)
			}

			// Restore original args
			os.Args = oldArgs
		})
	}
}

func TestStartRatify(t *testing.T) {
	startManagerFunc = func(_ chan struct{}, _, _, _ bool) {}
	tests := []struct {
		name        string
		opts        *options
		expectError bool
	}{
		{
			name: "missing http server address",
			opts: &options{
				configFilePath:      "config.yaml",
				verifyTimeout:       5 * time.Second,
				disableCertRotation: true,
				disableCRDManager:   true,
			},
			expectError: true,
		},
		{
			name: "failed to start the server",
			opts: &options{
				httpServerAddress:   ":8080",
				configFilePath:      "config.yaml",
				certFile:            "cert.pem",
				disableCertRotation: true,
				disableCRDManager:   true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := startRatify(tt.opts)
			if (err != nil) != tt.expectError {
				t.Errorf("startRatify() error = %v, expectError %v", err, tt.expectError)
			}
		})
	}
}

func TestRunHealthServer(t *testing.T) {
	t.Run("empty address is a no-op", func(_ *testing.T) {
		// Should return immediately without starting a server.
		runHealthServer(context.Background(), "", nil)
	})

	t.Run("stops when context is cancelled", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to reserve a port: %v", err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			runHealthServer(ctx, addr, nil)
			close(done)
		}()

		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("runHealthServer did not stop after context cancel")
		}
	})

	t.Run("returns on invalid address", func(_ *testing.T) {
		// An out-of-range port makes the server fail to listen and return,
		// exercising the error-logging branch.
		runHealthServer(context.Background(), "127.0.0.1:99999", nil)
	})
}
