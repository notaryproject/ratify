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

package metrics

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/sdk/metric"
)

const prometheusExporter = "prometheus"

var MetricReader metric.Reader

// InitMetricsExporter initializes the metrics exporter for the specified metrics backend and port
func InitMetricsExporter(metricsBackend string, port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("invalid port %v", port)
	}
	mb := strings.ToLower(metricsBackend)
	logrus.Info("initializing metrics backend: ", mb)
	switch mb {
	// Prometheus is the only exporter for now
	case prometheusExporter:
		var err error
		MetricReader, err = prometheus.New()
		if err != nil {
			logrus.Error(err)
			return err
		}
		if err := initPrometheusExporter(port); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported metrics backend %v", metricsBackend)
	}
	return initStatsReporter()
}
