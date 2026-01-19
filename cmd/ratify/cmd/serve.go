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

package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ratify-project/ratify/config"
	"github.com/ratify-project/ratify/httpserver"
	"github.com/ratify-project/ratify/internal/logger"
	"github.com/ratify-project/ratify/pkg/cache"
	"github.com/ratify-project/ratify/pkg/manager"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	serveUse = "serve"
)

type serveCmdOptions struct {
	configFilePath    string
	httpServerAddress string
	certDirectory     string
	caCertFiles       string
	enableCrdManager  bool
	cacheEnabled      bool
	cacheType         string
	cacheName         string
	cacheSize         int
	cacheTTL          time.Duration
	metricsEnabled    bool
	metricsType       string
	metricsPort       int
	healthPort        string
}

func NewCmdServe(_ ...string) *cobra.Command {
	var opts serveCmdOptions

	cmd := &cobra.Command{
		Use:     serveUse,
		Short:   "Run ratify as a server",
		Example: "ratify server",
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return serve(opts)
		},
	}

	flags := cmd.Flags()

	flags.StringVar(&opts.httpServerAddress, "http", "", "HTTP Address")
	flags.StringVarP(&opts.configFilePath, "config", "c", "", "Config File Path")
	flags.StringVar(&opts.certDirectory, "cert-dir", "", "Path to ratify certs")
	flags.StringVar(&opts.caCertFiles, "ca-cert-files", "", "Path to CA cert files")
	flags.BoolVar(&opts.enableCrdManager, "enable-crd-manager", false, "Start crd manager if enabled (default: false)")
	flags.BoolVar(&opts.cacheEnabled, "cache-enabled", false, "Enable cache if enabled (default: false)")
	flags.StringVar(&opts.cacheType, "cache-type", cache.DefaultCacheType, fmt.Sprintf("Cache type to use (default: %s)", cache.DefaultCacheType))
	flags.StringVar(&opts.cacheName, "cache-name", cache.DefaultCacheName, fmt.Sprintf("Cache implementation name to use (default: %s)", cache.DefaultCacheName))
	flags.IntVar(&opts.cacheSize, "cache-size", cache.DefaultCacheSize, fmt.Sprintf("Cache max size to use in MB (default: %d)", cache.DefaultCacheSize))
	flags.DurationVar(&opts.cacheTTL, "cache-ttl", cache.DefaultCacheTTL, fmt.Sprintf("Cache TTL for the verifier http server (default: %fs)", cache.DefaultCacheTTL.Seconds()))
	flags.BoolVar(&opts.metricsEnabled, "metrics-enabled", false, "Enable metrics exporter if enabled (default: false)")
	flags.StringVar(&opts.metricsType, "metrics-type", httpserver.DefaultMetricsType, fmt.Sprintf("Metrics exporter type to use (default: %s)", httpserver.DefaultMetricsType))
	flags.IntVar(&opts.metricsPort, "metrics-port", httpserver.DefaultMetricsPort, fmt.Sprintf("Metrics exporter port to use (default: %d)", httpserver.DefaultMetricsPort))
	flags.StringVar(&opts.healthPort, "health-port", httpserver.DefaultHealthPort, fmt.Sprintf("Health port to use (default: %s)", httpserver.DefaultHealthPort))
	return cmd
}

func serve(opts serveCmdOptions) error {
	if opts.cacheEnabled {
		// initialize global cache of specified type
		if _, err := cache.NewCacheProvider(context.TODO(), opts.cacheType, opts.cacheName, opts.cacheSize); err != nil {
			return fmt.Errorf("error initializing cache of type %s: %w", opts.cacheType, err)
		}
		logrus.Debugf("initialized cache of type %s", opts.cacheType)
	}
	logConfig, err := config.GetLoggerConfig(opts.configFilePath)
	if err != nil {
		return fmt.Errorf("failed to retrieve logger configuration: %w", err)
	}
	if err := logger.InitLogConfig(logConfig); err != nil {
		return fmt.Errorf("failed to initialize logger configuration: %w", err)
	}

	// in crd mode, the manager gets latest store/verifier from crd and pass on to the http server
	if opts.enableCrdManager {
		certRotatorReady := make(chan struct{})
		logrus.Infof("starting crd manager")
		go manager.StartManager(certRotatorReady, opts.healthPort)
		manager.StartServer(opts.httpServerAddress, opts.configFilePath, opts.certDirectory, strings.Split(opts.caCertFiles, ","), opts.cacheTTL, opts.metricsEnabled, opts.metricsType, opts.metricsPort, certRotatorReady)

		return nil
	}

	getExecutor, err := config.GetExecutorAndWatchForUpdate(opts.configFilePath)
	if err != nil {
		return err
	}

	if opts.httpServerAddress != "" {
		server, err := httpserver.NewServer(context.Background(), opts.httpServerAddress, getExecutor, opts.certDirectory, strings.Split(opts.caCertFiles, ","), opts.cacheTTL, opts.metricsEnabled, opts.metricsType, opts.metricsPort)
		if err != nil {
			return err
		}
		logrus.Infof("starting server at %s", opts.httpServerAddress)
		if err := server.Run(nil); err != nil {
			return err
		}
	}

	return nil
}
