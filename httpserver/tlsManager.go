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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"
)

// This implementation is based on K8s certwatcher: https://github.com/kubernetes-sigs/controller-runtime/blob/main/pkg/certwatcher/certwatcher.go
type TLSCertWatcher struct {
	sync.RWMutex
	ratifyServerCert *tls.Certificate
	clientCACert     *x509.CertPool
	watcher          *fsnotify.Watcher

	ratifyServerCertPath string
	ratifyServerKeyPath  string
	clientCACertPaths    []string
}

// NewTLSCertWatcher creates a new TLSCertWatcher for ratify tls cert/key paths and client CA cert paths
func NewTLSCertWatcher(ratifyServerCertPath, ratifyServerKeyPath string, clientCACertPaths []string) (*TLSCertWatcher, error) {
	var err error
	certWatcher := &TLSCertWatcher{
		ratifyServerCertPath: ratifyServerCertPath,
		ratifyServerKeyPath:  ratifyServerKeyPath,
		clientCACertPaths:    clientCACertPaths,
	}

	if err = certWatcher.ReadCertificates(); err != nil {
		return nil, err
	}

	certWatcher.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	return certWatcher, nil
}

// Start adds the files to watcher and starts the certificate watcher routine
func (t *TLSCertWatcher) Start() error {
	files := map[string]struct{}{t.ratifyServerCertPath: {}, t.ratifyServerKeyPath: {}}
	for _, certPath := range t.clientCACertPaths {
		if certPath != "" {
			files[certPath] = struct{}{}
		}
	}

	{
		var watchErr error
		pollInterval := 1 * time.Second
		pollTimeout := 10 * time.Second
		if err := wait.PollUntilContextTimeout(context.TODO(), pollInterval, pollTimeout, false, func(_ context.Context) (done bool, err error) {
			for f := range files {
				if err := t.watcher.Add(f); err != nil {
					watchErr = err
					return false, nil //nolint:nilerr // we want to keep trying.
				}
				// remove it from the set
				delete(files, f)
			}
			return true, nil
		}); err != nil {
			return fmt.Errorf("failed to add watches: %w: %s", err, watchErr.Error())
		}
	}

	logrus.Info("Starting TLS certificate watcher")
	go t.Watch()

	return nil
}

// Stop closes the watcher
func (t *TLSCertWatcher) Stop() {
	if err := t.watcher.Close(); err != nil {
		logrus.Errorf("error closing certificate watcher: %v", err)
	}
}

// ReadCertificates reads the certificates from the cert/key paths
func (t *TLSCertWatcher) ReadCertificates() error {
	if t.ratifyServerCertPath == "" || t.ratifyServerKeyPath == "" {
		return fmt.Errorf("ratify server cert or key path is empty")
	}

	clientCAs := x509.NewCertPool()
	for _, certPath := range t.clientCACertPaths {
		if certPath != "" {
			caCert, err := os.ReadFile(certPath)
			if err != nil {
				return fmt.Errorf("error reading CA cert from %s: %w", certPath, err)
			}
			if !clientCAs.AppendCertsFromPEM(caCert) {
				return fmt.Errorf("failed to append CA cert from %s", certPath)
			}
		}
	}

	if len(t.clientCACertPaths) > 0 {
		t.Lock()
		t.clientCACert = clientCAs
		t.Unlock()
	}

	ratifyServerCert, err := tls.LoadX509KeyPair(t.ratifyServerCertPath, t.ratifyServerKeyPath)
	if err != nil {
		return err
	}
	t.Lock()
	t.ratifyServerCert = &ratifyServerCert
	t.Unlock()
	return nil
}

// GetConfigForClient returns the tls config for the client use in the TLS Config
func (t *TLSCertWatcher) GetConfigForClient(*tls.ClientHelloInfo) (*tls.Config, error) {
	t.RLock()
	defer t.RUnlock()

	config := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{*t.ratifyServerCert},
		GetConfigForClient: t.GetConfigForClient,
	}

	if t.clientCACert != nil {
		config.ClientCAs = t.clientCACert
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return config, nil
}

func (t *TLSCertWatcher) handleEvent(event fsnotify.Event) {
	// Only care about events which may modify the contents of the file.
	if !isWrite(event) && !isRemove(event) && !isCreate(event) {
		return
	}

	logrus.Infof("tls certificate rotation event: %v", event)

	// If the file was removed, re-add the watch.
	if isRemove(event) {
		if err := t.watcher.Add(event.Name); err != nil {
			logrus.Errorf("error re-watching file: %v", err)
		}
	}

	if err := t.ReadCertificates(); err != nil {
		logrus.Errorf("error re-reading certificates: %v", err)
	}
}

// Watch watches the certificate files for changes and terminates on error/stop
func (t *TLSCertWatcher) Watch() {
	for {
		select {
		case event, ok := <-t.watcher.Events:
			// Channel is closed.
			if !ok {
				return
			}

			t.handleEvent(event)

		case err, ok := <-t.watcher.Errors:
			// Channel is closed.
			if !ok {
				return
			}

			logrus.Errorf("certificate watch error: %v", err)
		}
	}
}

func isWrite(event fsnotify.Event) bool {
	return event.Op == fsnotify.Write
}

func isCreate(event fsnotify.Event) bool {
	return event.Op == fsnotify.Create
}

func isRemove(event fsnotify.Event) bool {
	return event.Op == fsnotify.Remove
}
