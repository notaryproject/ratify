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
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/ratify-project/ratify/config"
	"github.com/ratify-project/ratify/internal/logger"
	"github.com/ratify-project/ratify/pkg/metrics"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

const (
	ServerRootURL                    = "/ratify/gatekeeper/v1"
	certName                         = "tls.crt"
	keyName                          = "tls.key"
	readHeaderTimeout                = 5 * time.Second
	idleTimeout                      = 90 * time.Second
	defaultMutationReferrerStoreName = "oras"

	DefaultMetricsType = "prometheus"
	DefaultMetricsPort = 8888
	DefaultHealthPort  = ":9099"
)

type Server struct {
	Address           string
	Router            *mux.Router
	GetExecutor       config.GetExecutor
	Context           context.Context
	CertDirectory     string
	CaCertFiles       []string
	MutationStoreName string
	MetricsEnabled    bool
	MetricsType       string
	MetricsPort       int
	CacheTTL          time.Duration
	LogOption         logger.Option

	keyMutex keyMutex
}

// keyMutex is a thread-safe map of mutexes, indexed by key.
type keyMutex struct {
	locks sync.Map
}

// Lock locks the mutex for the given key, and returns a function to unlock it.
func (m *keyMutex) Lock(key string) func() {
	v, _ := m.locks.LoadOrStore(key, &sync.Mutex{})
	v.(*sync.Mutex).Lock()
	return func() {
		v.(*sync.Mutex).Unlock()
	}
}

func NewServer(context context.Context,
	address string,
	getExecutor config.GetExecutor,
	certDir string,
	caCertFiles []string,
	cacheTTL time.Duration,
	metricsEnabled bool,
	metricsType string,
	metricsPort int) (*Server, error) {
	if address == "" {
		return nil, ServerAddrNotFoundError{}
	}

	server := &Server{
		Address:           address,
		GetExecutor:       getExecutor,
		Router:            mux.NewRouter(),
		Context:           context,
		CertDirectory:     certDir,
		CaCertFiles:       caCertFiles,
		MutationStoreName: defaultMutationReferrerStoreName,
		MetricsEnabled:    metricsEnabled,
		MetricsType:       metricsType,
		MetricsPort:       metricsPort,
		CacheTTL:          cacheTTL,
		keyMutex:          keyMutex{},
		LogOption:         logger.Option{ComponentType: logger.Server},
	}

	return server, server.registerHandlers()
}

func (server *Server) Run(certRotatorReady chan struct{}) error {
	tcpAddr, err := net.ResolveTCPAddr("tcp", server.Address)
	if err != nil {
		return err
	}

	// initialize metrics exporters
	if server.MetricsEnabled {
		if err := metrics.InitMetricsExporter(server.MetricsType, server.MetricsPort); err != nil {
			logrus.Errorf("failed to initialize metrics exporter %s: %v", server.MetricsType, err)
			os.Exit(1)
		}
	}

	lsnr, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}

	svr := &http.Server{
		Addr:              server.Address,
		Handler:           server.Router,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}

	if server.CertDirectory != "" {
		if certRotatorReady != nil {
			<-certRotatorReady
		}
		certFile := filepath.Join(server.CertDirectory, certName)
		keyFile := filepath.Join(server.CertDirectory, keyName)

		logrus.Info(fmt.Sprintf("%s: [%s:%s] [%s:%s]", "starting server using TLS", "certFile", certFile, "keyFile", keyFile))

		tlsCertWatcher, err := NewTLSCertWatcher(certFile, keyFile, server.CaCertFiles)
		if err != nil {
			return err
		}
		if err = tlsCertWatcher.Start(); err != nil {
			return err
		}
		defer tlsCertWatcher.Stop()
		if err = tlsCertWatcher.ReadCertificates(); err != nil {
			return err
		}

		svr.TLSConfig = &tls.Config{
			GetConfigForClient: tlsCertWatcher.GetConfigForClient,
			MinVersion:         tls.VersionTLS13,
		}

		return startServerWithGracefulShutdown(true, svr, lsnr, certFile, keyFile)
	}
	return startServerWithGracefulShutdown(false, svr, lsnr, "", "")
}

func (server *Server) register(method, path string, handler ContextHandler) {
	server.Router.Methods(method).Path(path).Handler(&contextHandler{
		context: server.Context,
		handler: handler,
	})
}

func (server *Server) registerHandlers() error {
	verifyPath, err := url.JoinPath(ServerRootURL, "verify")
	if err != nil {
		return err
	}
	server.register(http.MethodPost, verifyPath, processTimeout(server.verify, server.GetExecutor(server.Context).GetVerifyRequestTimeout(), false))

	mutatePath, err := url.JoinPath(ServerRootURL, "mutate")
	if err != nil {
		return err
	}
	server.register(http.MethodPost, mutatePath, processTimeout(server.mutate, server.GetExecutor(server.Context).GetMutationRequestTimeout(), true))

	return nil
}

type ServerAddrNotFoundError struct{}

func (err ServerAddrNotFoundError) Error() string {
	return "The http server address configuration is not set. Skipping server creation"
}

// startServerWithGracefulShutdown starts the server and waits for SIGINT or SIGTERM to shutdown the server gracefully
func startServerWithGracefulShutdown(isTLSEnabled bool, svr *http.Server, lsnr net.Listener, certFile string, keyFile string) error {
	connectionsClosed := make(chan struct{})
	// wait for SIGINT or SIGTERM to shutdown the server gracefully
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)
		<-sigint
		logrus.Info("shutting down ratify server...")
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second) // wait 6 seconds for existing connections to finish
		defer cancel()
		if err := svr.Shutdown(ctx); err != nil {
			logrus.Errorf("failed to shutdown ratify server: %v", err)
		}
		close(connectionsClosed)
	}()
	if isTLSEnabled {
		if err := svr.ServeTLS(lsnr, certFile, keyFile); err != nil && err != http.ErrServerClosed { // http.ErrServerClosed is immediately returned when server.Shutdown() is called
			logrus.Errorf("failed to start server: %v", err)
			return err
		}
	} else {
		if err := svr.Serve(lsnr); err != nil && err != http.ErrServerClosed { // http.ErrServerClosed is immediately returned when server.Shutdown() is called
			logrus.Errorf("failed to start server: %v", err)
			return err
		}
	}
	<-connectionsClosed // wait for server to shutdown
	logrus.Info("ratify server shutdown complete")
	time.Sleep(5 * time.Second) // wait for controllers/manager to shutdown
	return nil
}
