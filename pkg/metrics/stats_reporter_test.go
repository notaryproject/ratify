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
	"fmt"
	"testing"

	ctxUtils "github.com/notaryproject/ratify/v2/internal/context"
	"go.opentelemetry.io/otel/attribute"
	instrument "go.opentelemetry.io/otel/metric"
)

const testNamespace = "testNamespace"

type MockInt64Histogram struct {
	instrument.Int64Histogram
	Value      int64
	Attributes map[string]string
}

func (m *MockInt64Histogram) Record(_ context.Context, incr int64, options ...instrument.RecordOption) {
	m.Value = incr
	opts := instrument.NewRecordConfig(options).Attributes()
	for _, attr := range opts.ToSlice() {
		setValue := attr.Value.AsString()
		if attr.Value.Type() == attribute.BOOL {
			setValue = fmt.Sprintf("%t", attr.Value.AsBool())
		}
		m.Attributes[string(attr.Key)] = setValue
	}
}

func (m *MockInt64Counter) Add(_ context.Context, incr int64, options ...instrument.AddOption) {
	m.Value = incr
	opts := instrument.NewAddConfig(options).Attributes()
	for _, attr := range opts.ToSlice() {
		setValue := attr.Value.AsString()
		if attr.Value.Type() == attribute.INT64 {
			setValue = fmt.Sprintf("%d", attr.Value.AsInt64())
		} else if attr.Value.Type() == attribute.BOOL {
			setValue = fmt.Sprintf("%t", attr.Value.AsBool())
		}
		m.Attributes[string(attr.Key)] = setValue
	}
}

type MockInt64Counter struct {
	instrument.Int64Counter
	Value      int64
	Attributes map[string]string
}

func TestReportVerificationRequest(t *testing.T) {
	if err := initStatsReporter(); err != nil {
		t.Fatalf("initStatsReporter() error = %v", err)
	}

	mockDuration := &MockInt64Histogram{}
	verificationDuration = mockDuration
	ReportVerificationRequest(context.Background(), 5)
	if mockDuration.Value != 5 {
		t.Fatalf("ReportVerificationRequest() mockDuration.Value = %v, expected %v", mockDuration.Value, 5)
	}
}

func TestReportMutationRequest(t *testing.T) {
	if err := initStatsReporter(); err != nil {
		t.Fatalf("initStatsReporter() error = %v", err)
	}

	mockDuration := &MockInt64Histogram{}
	mutationDuration = mockDuration
	ReportMutationRequest(context.Background(), 5)
	if mockDuration.Value != 5 {
		t.Fatalf("ReportMutationRequest() mockDuration.Value = %v, expected %v", mockDuration.Value, 5)
	}
}

func TestReportVerifierDuration(t *testing.T) {
	if err := initStatsReporter(); err != nil {
		t.Fatalf("initStatsReporter() error = %v", err)
	}

	mockDuration := &MockInt64Histogram{Attributes: make(map[string]string)}
	verifierDuration = mockDuration
	ctx := ctxUtils.SetContextWithNamespace(context.Background(), testNamespace)
	ReportVerifierDuration(ctx, 5, "test_verifier", "test_subject", true, true)
	if mockDuration.Value != 5 {
		t.Fatalf("ReportVerifierDuration() mockDuration.Value = %v, expected %v", mockDuration.Value, 5)
	}
	if len(mockDuration.Attributes) != 5 {
		t.Fatalf("ReportVerifierDuration() len(mockDuration.Attributes) = %v, expected %v", len(mockDuration.Attributes), 2)
	}
	if mockDuration.Attributes["verifier"] != "test_verifier" {
		t.Fatalf("expected verifer attribute to be test_verifier but got %s", mockDuration.Attributes["verifier"])
	}
	if mockDuration.Attributes["subject"] != "test_subject" {
		t.Fatalf("expected subject attribute to be test_subject but got %s", mockDuration.Attributes["subject"])
	}
	if mockDuration.Attributes["error"] != "true" {
		t.Fatalf("expected error attribute to be true but got %s", mockDuration.Attributes["error"])
	}
	if mockDuration.Attributes["workload_namespace"] != testNamespace {
		t.Fatalf("expected workload_namespace attribute to be %s but got %s", testNamespace, mockDuration.Attributes["workload_namespac"])
	}
}

func TestReportSystemError(t *testing.T) {
	if err := initStatsReporter(); err != nil {
		t.Fatalf("initStatsReporter() error = %v", err)
	}

	mockCounter := &MockInt64Counter{Attributes: make(map[string]string)}
	systemErrorCount = mockCounter
	ctx := ctxUtils.SetContextWithNamespace(context.Background(), testNamespace)
	ReportSystemError(ctx, "test_error")
	if mockCounter.Value != 1 {
		t.Fatalf("ReportSystemError() mockCounter.Value = %v, expected %v", mockCounter.Value, 1)
	}
	if len(mockCounter.Attributes) != 2 {
		t.Fatalf("ReportSystemError() len(mockCounter.Attributes) = %v, expected %v", len(mockCounter.Attributes), 1)
	}
	if mockCounter.Attributes["error"] != "test_error" {
		t.Fatalf("expected error attributes to be test_error but got %s", mockCounter.Attributes["error"])
	}
	if mockCounter.Attributes["workload_namespace"] != testNamespace {
		t.Fatalf("expected workload_namespace attribute to be %s but got %s", testNamespace, mockCounter.Attributes["workload_namespac"])
	}
}

func TestReportRequestCount(t *testing.T) {
	if err := initStatsReporter(); err != nil {
		t.Fatalf("initStatsReporter() error = %v", err)
	}

	mockCounter := &MockInt64Counter{Attributes: make(map[string]string)}
	registryRequestCount = mockCounter
	ctx := ctxUtils.SetContextWithNamespace(context.Background(), testNamespace)
	ReportRegistryRequestCount(ctx, 429, "test_registry_host")
	if mockCounter.Value != 1 {
		t.Fatalf("ReportRequestCount() mockCounter.Value = %v, expected %v", mockCounter.Value, 1)
	}
	if len(mockCounter.Attributes) != 3 {
		t.Fatalf("ReportRequestCount() len(mockCounter.Attributes) = %v, expected %v", len(mockCounter.Attributes), 2)
	}
	if mockCounter.Attributes["status_code"] != "429" {
		t.Fatalf("expected status_code attribute to be 429 but got %s", mockCounter.Attributes["status_code"])
	}
	if mockCounter.Attributes["registry_host"] != "test_registry_host" {
		t.Fatalf("expected registry_host attribute to be test_registry_host but got %s", mockCounter.Attributes["registry_host"])
	}
	if mockCounter.Attributes["workload_namespace"] != testNamespace {
		t.Fatalf("expected workload_namespace attribute to be %s but got %s", testNamespace, mockCounter.Attributes["workload_namespac"])
	}
}

func TestReportAADExchangeDuration(t *testing.T) {
	if err := initStatsReporter(); err != nil {
		t.Fatalf("initStatsReporter() error = %v", err)
	}

	mockDuration := &MockInt64Histogram{Attributes: make(map[string]string)}
	aadExchangeDuration = mockDuration
	ctx := ctxUtils.SetContextWithNamespace(context.Background(), testNamespace)
	ReportAADExchangeDuration(ctx, 500, "test_scope")
	if mockDuration.Value != 500 {
		t.Fatalf("ReportAADExchangeDuration() mockDuration.Value = %v, expected %v", mockDuration.Value, 500)
	}
	if len(mockDuration.Attributes) != 2 {
		t.Fatalf("ReportAADExchangeDuration() len(mockDuration.Attributes) = %v, expected %v", len(mockDuration.Attributes), 1)
	}
	if mockDuration.Attributes["resource_type"] != "test_scope" {
		t.Fatalf("expected resource_type attribute to be test_scope but got %s", mockDuration.Attributes["resource_type"])
	}
	if mockDuration.Attributes["workload_namespace"] != testNamespace {
		t.Fatalf("expected workload_namespace attribute to be %s but got %s", testNamespace, mockDuration.Attributes["workload_namespac"])
	}
}

func TestReportACRExchangeDuration(t *testing.T) {
	if err := initStatsReporter(); err != nil {
		t.Fatalf("initStatsReporter() error = %v", err)
	}

	mockDuration := &MockInt64Histogram{Attributes: make(map[string]string)}
	acrExchangeDuration = mockDuration
	ctx := ctxUtils.SetContextWithNamespace(context.Background(), testNamespace)
	ReportACRExchangeDuration(ctx, 500, "test_repo")
	if mockDuration.Value != 500 {
		t.Fatalf("ReportACRExchangeDuration() mockDuration.Value = %v, expected %v", mockDuration.Value, 500)
	}
	if len(mockDuration.Attributes) != 2 {
		t.Fatalf("ReportACRExchangeDuration() len(mockDuration.Attributes) = %v, expected %v", len(mockDuration.Attributes), 1)
	}
	if mockDuration.Attributes["repository"] != "test_repo" {
		t.Fatalf("expected repository attribute to be test_repo but got %s", mockDuration.Attributes["repository"])
	}
	if mockDuration.Attributes["workload_namespace"] != testNamespace {
		t.Fatalf("expected workload_namespace attribute to be %s but got %s", testNamespace, mockDuration.Attributes["workload_namespac"])
	}
}

func TestReportAKVCertificateDuration(t *testing.T) {
	if err := initStatsReporter(); err != nil {
		t.Fatalf("initStatsReporter() error = %v", err)
	}

	mockDuration := &MockInt64Histogram{Attributes: make(map[string]string)}
	akvCertificateDuration = mockDuration
	ctx := ctxUtils.SetContextWithNamespace(context.Background(), testNamespace)
	ReportAKVCertificateDuration(ctx, 500, "test_cert")
	if mockDuration.Value != 500 {
		t.Fatalf("ReportAKVCertificateDuration() mockDuration.Value = %v, expected %v", mockDuration.Value, 500)
	}
	if len(mockDuration.Attributes) != 2 {
		t.Fatalf("ReportAKVCertificateDuration() len(mockDuration.Attributes) = %v, expected %v", len(mockDuration.Attributes), 1)
	}
	if mockDuration.Attributes["certificate_name"] != "test_cert" {
		t.Fatalf("expected certificate_name attribute to be test_cert but got %s", mockDuration.Attributes["certificate_name"])
	}
	if mockDuration.Attributes["workload_namespace"] != testNamespace {
		t.Fatalf("expected workload_namespace attribute to be %s but got %s", testNamespace, mockDuration.Attributes["workload_namespac"])
	}
}

func TestReportBlobCacheCount(t *testing.T) {
	if err := initStatsReporter(); err != nil {
		t.Fatalf("initStatsReporter() error = %v", err)
	}

	mockCounter := &MockInt64Counter{Attributes: make(map[string]string)}
	cacheBlobCount = mockCounter
	ctx := ctxUtils.SetContextWithNamespace(context.Background(), testNamespace)
	ReportBlobCacheCount(ctx, true)
	if mockCounter.Value != 1 {
		t.Fatalf("ReportBlobCacheCount() mockCounter.Value = %v, expected %v", mockCounter.Value, 1)
	}
	if len(mockCounter.Attributes) != 2 {
		t.Fatalf("ReportBlobCacheCount() len(mockCounter.Attributes) = %v, expected %v", len(mockCounter.Attributes), 1)
	}
	if mockCounter.Attributes["hit"] != "true" {
		t.Fatalf("expected hit attribute to be true but got %s", mockCounter.Attributes["hit"])
	}
	if mockCounter.Attributes["workload_namespace"] != testNamespace {
		t.Fatalf("expected workload_namespace attribute to be %s but got %s", testNamespace, mockCounter.Attributes["workload_namespac"])
	}
}

func TestReportVerificationResult(t *testing.T) {
	if err := initStatsReporter(); err != nil {
		t.Fatalf("initStatsReporter() error = %v", err)
	}

	mockCounter := &MockInt64Counter{Attributes: make(map[string]string)}
	verificationResultCount = mockCounter
	ctx := ctxUtils.SetContextWithNamespace(context.Background(), testNamespace)
	ReportVerificationResult(ctx, VerificationResultFailed, true)
	if mockCounter.Value != 1 {
		t.Fatalf("ReportVerificationResult() mockCounter.Value = %v, expected %v", mockCounter.Value, 1)
	}
	if len(mockCounter.Attributes) != 3 {
		t.Fatalf("ReportVerificationResult() len(mockCounter.Attributes) = %v, expected %v", len(mockCounter.Attributes), 3)
	}
	if mockCounter.Attributes["result"] != VerificationResultFailed {
		t.Fatalf("expected result attribute to be %s but got %s", VerificationResultFailed, mockCounter.Attributes["result"])
	}
	if mockCounter.Attributes["cache_hit"] != "true" {
		t.Fatalf("expected cache_hit attribute to be true but got %s", mockCounter.Attributes["cache_hit"])
	}
	if mockCounter.Attributes["workload_namespace"] != testNamespace {
		t.Fatalf("expected workload_namespace attribute to be %s but got %s", testNamespace, mockCounter.Attributes["workload_namespace"])
	}
}

func TestReportVerificationResult_Uninitialized(_ *testing.T) {
	verificationResultCount = nil
	// Must be a no-op rather than a nil dereference when metrics are disabled.
	ReportVerificationResult(context.Background(), VerificationResultSucceeded, false)
}
