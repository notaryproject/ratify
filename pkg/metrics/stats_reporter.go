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
	"context"

	ctxUtils "github.com/notaryproject/ratify/v2/internal/context"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	instrument "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

const attrKeyWorkloadNamespace = "workload_namespace"

var (
	// defines the metrics that are collected
	verificationDuration instrument.Int64Histogram
	mutationDuration     instrument.Int64Histogram
	verifierDuration     instrument.Int64Histogram
	systemErrorCount     instrument.Int64Counter
	registryRequestCount instrument.Int64Counter
	cacheBlobCount       instrument.Int64Counter

	// Azure Metrics
	aadExchangeDuration    instrument.Int64Histogram
	acrExchangeDuration    instrument.Int64Histogram
	akvCertificateDuration instrument.Int64Histogram
)

const (
	scope = "github.com/ratify-project/ratify"

	// metric names
	metricNameVerificationDuration = "ratify_verification_request"
	metricNameMutationDuration     = "ratify_mutation_request"
	metricNameVerifierDuration     = "ratify_verifier_duration"
	metricNameSystemErrorCount     = "ratify_system_error_count"
	metricNameRegistryRequestCount = "ratify_registry_request_count"
	metricNameBlobCacheCount       = "ratify_blob_cache_count"

	// Azure Metrics
	metricNameAADExchangeDuration    = "ratify_aad_exchange_duration"
	metricNameACRExchangeDuration    = "ratify_acr_exchange_duration"
	metricNameAKVCertificateDuration = "ratify_akv_certificate_duration"
)

// initStatsReporter creates defines data transformation and creates the metrics
func initStatsReporter() error {
	var err error
	// defines the data-stream transformation of histogram metrics
	// the boundaries of the histogram are based on historical data observed and attempt to minimize the error of quantile estimation
	// NOTE: https://prometheus.io/docs/practices/histograms/#errors-of-quantile-estimation
	views := []sdkmetric.View{
		sdkmetric.NewView(
			sdkmetric.Instrument{
				Name:  metricNameVerificationDuration,
				Scope: instrumentation.Scope{Name: scope},
			},
			sdkmetric.Stream{
				Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
					Boundaries: []float64{0, 10, 30, 50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200, 1400, 1600, 1800, 2000, 2300, 2600, 4000, 4400, 4900},
				},
			},
		),
		sdkmetric.NewView(
			sdkmetric.Instrument{
				Name:  metricNameMutationDuration,
				Scope: instrumentation.Scope{Name: scope},
			},
			sdkmetric.Stream{
				Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
					Boundaries: []float64{0, 10, 30, 50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200, 1400, 1600, 1800},
				},
			},
		),
		sdkmetric.NewView(
			sdkmetric.Instrument{
				Name:  metricNameVerifierDuration,
				Scope: instrumentation.Scope{Name: scope},
			},
			sdkmetric.Stream{
				Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
					Boundaries: []float64{0, 10, 50, 100, 200, 300, 400, 600, 800, 1100, 1500, 2000},
				},
			},
		),
		sdkmetric.NewView(
			sdkmetric.Instrument{
				Name:  metricNameAADExchangeDuration,
				Scope: instrumentation.Scope{Name: scope},
			},
			sdkmetric.Stream{
				Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
					Boundaries: []float64{0, 10, 50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1200},
				},
			},
		),
		sdkmetric.NewView(
			sdkmetric.Instrument{
				Name:  metricNameACRExchangeDuration,
				Scope: instrumentation.Scope{Name: scope},
			},
			sdkmetric.Stream{
				Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
					Boundaries: []float64{0, 10, 50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1200},
				},
			},
		),
		sdkmetric.NewView(
			sdkmetric.Instrument{
				Name:  metricNameAKVCertificateDuration,
				Scope: instrumentation.Scope{Name: scope},
			},
			sdkmetric.Stream{
				Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
					Boundaries: []float64{0, 10, 50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1200},
				},
			},
		),
	}
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(MetricReader), sdkmetric.WithView(views...))
	meter := provider.Meter(scope)
	verificationDuration, err = meter.Int64Histogram(metricNameVerificationDuration, instrument.WithUnit("millisecond"), instrument.WithDescription("verification request duration in ms"))
	if err != nil {
		logrus.Error(err)
		return err
	}
	mutationDuration, err = meter.Int64Histogram(metricNameMutationDuration, instrument.WithUnit("millisecond"), instrument.WithDescription("mutation request duration in ms"))
	if err != nil {
		logrus.Error(err)
		return err
	}
	verifierDuration, err = meter.Int64Histogram(metricNameVerifierDuration, instrument.WithUnit("millisecond"), instrument.WithDescription("verifier duration in ms"))
	if err != nil {
		logrus.Error(err)
		return err
	}
	systemErrorCount, err = meter.Int64Counter(metricNameSystemErrorCount, instrument.WithDescription("system error count"))
	if err != nil {
		logrus.Error(err)
		return err
	}
	registryRequestCount, err = meter.Int64Counter(metricNameRegistryRequestCount, instrument.WithDescription("registry request count"))
	if err != nil {
		logrus.Error(err)
		return err
	}
	aadExchangeDuration, err = meter.Int64Histogram(metricNameAADExchangeDuration, instrument.WithUnit("millisecond"), instrument.WithDescription("AAD exchange duration in ms"))
	if err != nil {
		logrus.Error(err)
		return err
	}
	acrExchangeDuration, err = meter.Int64Histogram(metricNameACRExchangeDuration, instrument.WithUnit("millisecond"), instrument.WithDescription("ACR exchange duration in ms"))
	if err != nil {
		logrus.Error(err)
		return err
	}
	akvCertificateDuration, err = meter.Int64Histogram(metricNameAKVCertificateDuration, instrument.WithUnit("millisecond"), instrument.WithDescription("AKV certificate duration in ms"))
	if err != nil {
		logrus.Error(err)
		return err
	}
	cacheBlobCount, err = meter.Int64Counter(metricNameBlobCacheCount, instrument.WithDescription("blob cache hit/miss count"))
	if err != nil {
		logrus.Error(err)
		return err
	}
	return nil
}

// ReportVerificationRequest reports the duration of a verification request
func ReportVerificationRequest(ctx context.Context, duration int64) {
	if verificationDuration != nil {
		verificationDuration.Record(ctx, duration)
	}
}

// ReportMutationRequest reports the duration of a mutation request
func ReportMutationRequest(ctx context.Context, duration int64) {
	if mutationDuration != nil {
		mutationDuration.Record(ctx, duration)
	}
}

// ReportVerifierDuration reports the duration of a single verifier's execution
// Attributes:
// verifierName: the name of the verifier
// subjectReference: the subject reference of the verification
// success: whether the verification succeeded
// isError: whether the verification failed due to an error
// workload_namespace: the namespace where workload is deployed
func ReportVerifierDuration(ctx context.Context, duration int64, veriferName string, subjectReference string, success bool, isError bool) {
	if verifierDuration != nil {
		verifierDuration.Record(ctx, duration, instrument.WithAttributes(
			attribute.KeyValue{
				Key:   "verifier",
				Value: attribute.StringValue(veriferName),
			},
			attribute.KeyValue{
				Key:   "subject",
				Value: attribute.StringValue(subjectReference),
			},
			attribute.KeyValue{
				Key:   "success",
				Value: attribute.BoolValue(success),
			},
			attribute.KeyValue{
				Key:   "error",
				Value: attribute.BoolValue(isError),
			},
			attribute.KeyValue{
				Key:   attrKeyWorkloadNamespace,
				Value: attribute.StringValue(ctxUtils.GetNamespace(ctx)),
			},
		))
	}
}

// ReportSystemError reports a system error from the server handler
// Attributes:
// errorString: the error message
// workload_namespace: the namespace where workload is deployed
func ReportSystemError(ctx context.Context, errorString string) {
	if systemErrorCount != nil {
		systemErrorCount.Add(ctx, 1, instrument.WithAttributes(
			attribute.KeyValue{Key: "error", Value: attribute.StringValue(errorString)},
			attribute.KeyValue{Key: attrKeyWorkloadNamespace, Value: attribute.StringValue(ctxUtils.GetNamespace(ctx))}))
	}
}

// ReportRegistryRequestCount reports a registry request
// Attributes:
// statusCode: the status code of the request
// registryHost: the host name of the registry
// workload_namespace: the namespace where workload is deployed
func ReportRegistryRequestCount(ctx context.Context, statusCode int, registryHost string) {
	if registryRequestCount != nil {
		registryRequestCount.Add(ctx, 1, instrument.WithAttributes(
			attribute.KeyValue{Key: "status_code", Value: attribute.IntValue(statusCode)},
			attribute.KeyValue{Key: "registry_host", Value: attribute.StringValue(registryHost)},
			attribute.KeyValue{Key: attrKeyWorkloadNamespace, Value: attribute.StringValue(ctxUtils.GetNamespace(ctx))}))
	}
}

// ReportAADExchangeDuration reports the duration of an AAD exchange
// Attributes:
// resourceType: the scope of resource being exchanged (AKV or ACR)
// workload_namespace: the namespace where workload is deployed
func ReportAADExchangeDuration(ctx context.Context, duration int64, resourceType string) {
	if aadExchangeDuration != nil {
		aadExchangeDuration.Record(ctx, duration, instrument.WithAttributes(
			attribute.KeyValue{Key: "resource_type", Value: attribute.StringValue(resourceType)},
			attribute.KeyValue{Key: attrKeyWorkloadNamespace, Value: attribute.StringValue(ctxUtils.GetNamespace(ctx))}))
	}
}

// ReportACRExchangeDuration reports the duration of an ACR exchange (AAD token for ACR refresh token)
// Attributes:
// repository: the repository being accessed
// workload_namespace: the namespace where workload is deployed
func ReportACRExchangeDuration(ctx context.Context, duration int64, repository string) {
	if acrExchangeDuration != nil {
		acrExchangeDuration.Record(ctx, duration, instrument.WithAttributes(
			attribute.KeyValue{Key: "repository", Value: attribute.StringValue(repository)},
			attribute.KeyValue{Key: attrKeyWorkloadNamespace, Value: attribute.StringValue(ctxUtils.GetNamespace(ctx))}))
	}
}

// ReportAKVCertificateDuration reports the duration of an AKV certificate fetch
// Attributes:
// certificateName: the object name of the certificate
// workload_namespace: the namespace where workload is deployed
func ReportAKVCertificateDuration(ctx context.Context, duration int64, certificateName string) {
	if akvCertificateDuration != nil {
		akvCertificateDuration.Record(ctx, duration, instrument.WithAttributes(
			attribute.KeyValue{Key: "certificate_name", Value: attribute.StringValue(certificateName)},
			attribute.KeyValue{Key: attrKeyWorkloadNamespace, Value: attribute.StringValue(ctxUtils.GetNamespace(ctx))}))
	}
}

// ReportBlobCacheCount reports a blob cache hit or miss
// Attributes:
// hit: whether the blob was found in the cache
// workload_namespace: the namespace where workload is deployed
func ReportBlobCacheCount(ctx context.Context, hit bool) {
	if cacheBlobCount != nil {
		cacheBlobCount.Add(ctx, 1, instrument.WithAttributes(
			attribute.KeyValue{Key: "hit", Value: attribute.BoolValue(hit)},
			attribute.KeyValue{Key: attrKeyWorkloadNamespace, Value: attribute.StringValue(ctxUtils.GetNamespace(ctx))}))
	}
}
