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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/notaryproject/ratify/v2/internal/executor"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"golang.org/x/sync/singleflight"
)

type mockCache struct {
	entries map[string]string
}

func (c *mockCache) Get(_ context.Context, key string) (string, error) {
	if val, ok := c.entries[key]; ok {
		return val, nil
	}
	return "", fmt.Errorf("key not found")
}

func (c *mockCache) Set(_ context.Context, key string, value string, _ time.Duration) error {
	c.entries[key] = value
	return nil
}

func (c *mockCache) Delete(_ context.Context, key string) error {
	delete(c.entries, key)
	return nil
}

type mockResultCache struct {
	entries map[string]*result
}

func (c *mockResultCache) Get(_ context.Context, key string) (*result, error) {
	if val, ok := c.entries[key]; ok {
		return val, nil
	}
	return nil, fmt.Errorf("key not found")
}

func (c *mockResultCache) Set(_ context.Context, key string, value *result, _ time.Duration) error {
	c.entries[key] = value
	return nil
}

func (c *mockResultCache) Delete(_ context.Context, key string) error {
	delete(c.entries, key)
	return nil
}

func TestVerify(t *testing.T) {
	server := &server{
		getExecutor: func(_ string) *executor.ScopedExecutor {
			return &executor.ScopedExecutor{}
		},
		verifyCache: &mockResultCache{entries: make(map[string]*result)},
		sfGroup:     new(singleflight.Group),
	}

	tests := []struct {
		name            string
		requestBody     string
		expectedError   bool
		getExecutorFunc func(namespace string) *executor.ScopedExecutor
		cacheEntries    map[string]*result
		expectedItems   []externaldata.Item
	}{
		{
			name: "Valid request",
			requestBody: `{
				"request": {
					"keys": ["artifact1"]
				}
			}`,
			expectedError: false,
			expectedItems: []externaldata.Item{
				{
					Key:   "artifact1",
					Value: nil,
					Error: "failed to match executor for artifact \"artifact1\": failed to parse artifact reference \"artifact1\": invalid reference: missing registry or repository",
				},
			},
		},
		{
			name: "Failed to get executor",
			requestBody: `{
				"request": {
					"keys": ["artifact1"]
				}
			}`,
			getExecutorFunc: func(_ string) *executor.ScopedExecutor {
				return nil // Simulate failure to get executor
			},
			expectedError: false,
			expectedItems: []externaldata.Item{
				{
					Key:   "artifact1",
					Value: nil,
					Error: "no valid executor configured",
				},
			},
		},
		{
			name: "Valid request with cache hit",
			requestBody: `{
				"request": {
					"keys": ["artifact1"]
				}
			}`,
			cacheEntries: map[string]*result{
				"verify_artifact1": {
					Succeeded:       true,
					ArtifactReports: nil,
				},
			},
			expectedError: false,
			expectedItems: []externaldata.Item{
				{
					Key:   "artifact1",
					Value: map[string]interface{}{"succeeded": true, "artifactReports": nil},
				},
			},
		},
		{
			name:          "Invalid JSON",
			requestBody:   `{invalid-json}`,
			expectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/verify", strings.NewReader(test.requestBody))
			w := httptest.NewRecorder()

			if test.cacheEntries != nil {
				server.verifyCache = &mockResultCache{entries: test.cacheEntries}
			}
			if test.getExecutorFunc != nil {
				server.getExecutor = test.getExecutorFunc
			}
			err := server.verify(context.Background(), w, req)
			if (err != nil) != test.expectedError {
				t.Errorf("expected error: %v, got: %v", test.expectedError, err)
			}

			if !test.expectedError {
				var response externaldata.ProviderResponse
				if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				if !reflect.DeepEqual(response.Response.Items[0], test.expectedItems[0]) {
					t.Errorf("expected items: %v, got: %v", test.expectedItems, response.Response.Items)
				}
			}
		})
	}
}

func TestMutate(t *testing.T) {
	tests := []struct {
		name          string
		requestBody   string
		cacheEntries  map[string]string
		expectedError bool
		expectedItems []externaldata.Item
	}{
		{
			name: "Valid mutate request",
			requestBody: `{
				"request": {
					"keys": ["testrepo/testimage@sha256:498138d40d54f0fc20cd271e215366d3d8803f814b8f565b47c101480bbaaa88"]
				}
			}`,
			expectedError: false,
			expectedItems: []externaldata.Item{
				{
					Key:   "testrepo/testimage@sha256:498138d40d54f0fc20cd271e215366d3d8803f814b8f565b47c101480bbaaa88",
					Value: "testrepo/testimage@sha256:498138d40d54f0fc20cd271e215366d3d8803f814b8f565b47c101480bbaaa88",
				},
			},
		},
		{
			name:          "Invalid JSON mutate",
			requestBody:   `{invalid-json}`,
			expectedError: true,
		},
		{
			name: "Invalid reference",
			requestBody: `{
				"request": {
					"keys": ["testrepo"]
				}
			}`,
			expectedError: false,
			expectedItems: []externaldata.Item{
				{
					Key:   "testrepo",
					Value: "testrepo",
					Error: "failed to parse reference: invalid reference: missing registry or repository",
				},
			},
		},
		{
			name: "Cache hit",
			requestBody: `{
				"request": {
					"keys": ["testrepo/testimage:v1"]
				}
			}`,
			cacheEntries: map[string]string{
				"mutate_testrepo/testimage:v1": "testrepo/testimage@sha256:498138d40d54f0fc20cd271e215366d3d8803f814b8f565b47c101480bbaaa88",
			},
			expectedError: false,
			expectedItems: []externaldata.Item{
				{
					Key:   "testrepo/testimage:v1",
					Value: "testrepo/testimage@sha256:498138d40d54f0fc20cd271e215366d3d8803f814b8f565b47c101480bbaaa88",
				},
			},
		},
		{
			name: "Store fails to resolve reference",
			requestBody: `{
				"request": {
					"keys": ["testrepo/testimage:v1"]
				}
			}`,
			expectedError: false,
			expectedItems: []externaldata.Item{
				{
					Key:   "testrepo/testimage:v1",
					Value: "testrepo/testimage:v1",
					Error: "failed to match executor for artifact \"testrepo/testimage:v1\": no executor configured for the artifact \"testrepo/testimage:v1\"",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/mutate", strings.NewReader(test.requestBody))
			w := httptest.NewRecorder()

			server := &server{
				getExecutor: func(_ string) *executor.ScopedExecutor {
					return &executor.ScopedExecutor{}
				},
				mutateCache: &mockCache{entries: make(map[string]string)},
				sfGroup:     new(singleflight.Group),
			}
			if test.cacheEntries != nil {
				server.mutateCache = &mockCache{entries: test.cacheEntries}
			}
			if err := server.mutate(context.Background(), w, req); (err != nil) != test.expectedError {
				t.Errorf("expected error: %v, got: %v", test.expectedError, err)
			}

			if !test.expectedError {
				var response externaldata.ProviderResponse
				if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				if !reflect.DeepEqual(response.Response.Items, test.expectedItems) {
					t.Errorf("expected items: %v, got: %v", test.expectedItems, response.Response.Items)
				}
				if !response.Response.Idempotent {
					t.Errorf("expected Idempotent to be true for mutate, got false")
				}
			}
		})
	}
}

func TestExtractNamespace(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want string
	}{
		{"with namespace prefix", "[team-a]ghcr.io/org/image:v1", "team-a"},
		{"empty namespace prefix", "[]ghcr.io/org/image:v1", ""},
		{"no prefix", "ghcr.io/org/image:v1", ""},
		{"unterminated prefix", "[team-a ghcr.io/org/image:v1", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := extractNamespace(test.key); got != test.want {
				t.Errorf("extractNamespace(%q) = %q, want %q", test.key, got, test.want)
			}
		})
	}
}

func TestStripNamespacePrefix(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want string
	}{
		{"with namespace prefix", "[team-a]ghcr.io/org/image:v1", "ghcr.io/org/image:v1"},
		{"no prefix", "ghcr.io/org/image:v1", "ghcr.io/org/image:v1"},
		{"unterminated prefix", "[team-a ghcr.io/org/image:v1", "[team-a ghcr.io/org/image:v1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := stripNamespacePrefix(test.key); got != test.want {
				t.Errorf("stripNamespacePrefix(%q) = %q, want %q", test.key, got, test.want)
			}
		})
	}
}

// TestVerifyRoutesNamespace ensures the verify handler forwards the namespace
// extracted from the Gatekeeper key to the executor selector.
func TestVerifyRoutesNamespace(t *testing.T) {
	var gotNamespace string
	srv := &server{
		getExecutor: func(namespace string) *executor.ScopedExecutor {
			gotNamespace = namespace
			return nil // returning nil short-circuits with an error, which is fine here
		},
		sfGroup:     &singleflight.Group{},
		verifyCache: &mockResultCache{entries: make(map[string]*result)},
	}

	body := `{"apiVersion":"externaldata.gatekeeper.sh/v1beta1","kind":"ProviderRequest","request":{"keys":["[team-b]ghcr.io/org/image:v1"]}}`
	req := httptest.NewRequest(http.MethodPost, "/verify", strings.NewReader(body))
	w := httptest.NewRecorder()

	if err := srv.verify(context.Background(), w, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotNamespace != "team-b" {
		t.Errorf("expected namespace %q passed to getExecutor, got %q", "team-b", gotNamespace)
	}
}

// TestVerifyStripsNamespacePrefix ensures the verify handler forwards a
// namespace-prefixed Gatekeeper key to a real ScopedExecutor without the
// "[namespace]" prefix breaking reference parsing. With an executor that has no
// matching scope, the resulting error must be a "no executor configured" match
// error rather than a reference-parse failure.
func TestVerifyStripsNamespacePrefix(t *testing.T) {
	srv := &server{
		getExecutor: func(_ string) *executor.ScopedExecutor {
			return &executor.ScopedExecutor{}
		},
		sfGroup:     &singleflight.Group{},
		verifyCache: &mockResultCache{entries: make(map[string]*result)},
	}

	body := `{"apiVersion":"externaldata.gatekeeper.sh/v1beta1","kind":"ProviderRequest","request":{"keys":["[team-b]ghcr.io/org/image:v1"]}}`
	req := httptest.NewRequest(http.MethodPost, "/verify", strings.NewReader(body))
	w := httptest.NewRecorder()

	if err := srv.verify(context.Background(), w, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp externaldata.ProviderResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(resp.Response.Items) != 1 {
		t.Fatalf("expected 1 response item, got %d", len(resp.Response.Items))
	}
	itemErr := resp.Response.Items[0].Error
	if itemErr == "" {
		t.Fatal("expected an error for an unmatched artifact, got none")
	}
	if strings.Contains(itemErr, "parse") {
		t.Errorf("prefixed key should be stripped before parsing; got parse error: %q", itemErr)
	}
}

func newHandlerTestServer() *server {
	return &server{
		getExecutor: func(_ string) *executor.ScopedExecutor { return nil },
		sfGroup:     &singleflight.Group{},
		verifyCache: &mockResultCache{entries: make(map[string]*result)},
		mutateCache: &mockCache{entries: make(map[string]string)},
	}
}

// findEntry returns the first log entry at the given level whose message
// contains want. The logrus hook is global, so tests must match on their own
// message rather than assuming they are the only writer.
func findEntry(hook *test.Hook, level logrus.Level, want string) *logrus.Entry {
	for _, entry := range hook.AllEntries() {
		if entry.Level == level && strings.Contains(entry.Message, want) {
			return entry
		}
	}
	return nil
}

func TestVerifyHandler(t *testing.T) {
	srv := newHandlerTestServer()
	body := `{"apiVersion":"externaldata.gatekeeper.sh/v1beta1","kind":"ProviderRequest","request":{"keys":["ghcr.io/org/image:v1"]}}`
	req := httptest.NewRequest(http.MethodPost, "/verify", strings.NewReader(body))
	w := httptest.NewRecorder()

	srv.verifyHandler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("verifyHandler() status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestVerifyHandler_LogsFailure(t *testing.T) {
	hook := test.NewLocal(logrus.StandardLogger())
	defer hook.Reset()

	srv := newHandlerTestServer()
	req := httptest.NewRequest(http.MethodPost, "/verify", strings.NewReader("not json"))
	srv.verifyHandler().ServeHTTP(httptest.NewRecorder(), req)

	entry := findEntry(hook, logrus.ErrorLevel, "failed to handle the verification request")
	if entry == nil {
		t.Fatal("expected the verify handler to log the error it previously discarded")
	}
	if entry.Data["trace-id"] == nil {
		t.Error("expected the logged entry to carry a trace ID")
	}
}

func TestMutateHandler(t *testing.T) {
	srv := newHandlerTestServer()
	body := `{"apiVersion":"externaldata.gatekeeper.sh/v1beta1","kind":"ProviderRequest","request":{"keys":["ghcr.io/org/image:v1"]}}`
	req := httptest.NewRequest(http.MethodPost, "/mutate", strings.NewReader(body))
	w := httptest.NewRecorder()

	srv.mutateHandler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("mutateHandler() status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestMutateHandler_LogsFailure(t *testing.T) {
	hook := test.NewLocal(logrus.StandardLogger())
	defer hook.Reset()

	srv := newHandlerTestServer()
	req := httptest.NewRequest(http.MethodPost, "/mutate", strings.NewReader("not json"))
	srv.mutateHandler().ServeHTTP(httptest.NewRecorder(), req)

	entry := findEntry(hook, logrus.ErrorLevel, "failed to handle the mutation request")
	if entry == nil {
		t.Fatal("expected the mutate handler to log the error it previously discarded")
	}
	if entry.Data["trace-id"] == nil {
		t.Error("expected the logged entry to carry a trace ID")
	}
}

func TestVerify_LogsFailures(t *testing.T) {
	hook := test.NewLocal(logrus.StandardLogger())
	defer hook.Reset()

	srv := &server{
		getExecutor: func(_ string) *executor.ScopedExecutor { return nil },
		verifyCache: &mockResultCache{entries: make(map[string]*result)},
		sfGroup:     new(singleflight.Group),
	}
	req := httptest.NewRequest(http.MethodPost, "/verify", strings.NewReader(`{"request":{"keys":["artifact1"]}}`))
	if err := srv.verify(context.Background(), httptest.NewRecorder(), req); err != nil {
		t.Fatalf("verify() error = %v", err)
	}

	if findEntry(hook, logrus.ErrorLevel, "artifact1") == nil {
		t.Error("expected a verification failure for artifact1 to be logged at error level")
	}
}

func TestResolveReference_LogsFailures(t *testing.T) {
	hook := test.NewLocal(logrus.StandardLogger())
	defer hook.Reset()

	srv := &server{
		getExecutor: func(_ string) *executor.ScopedExecutor { return nil },
		mutateCache: &mockCache{entries: make(map[string]string)},
		sfGroup:     new(singleflight.Group),
	}
	if item := srv.resolveReference(context.Background(), "!invalid!"); item.Error == "" {
		t.Fatal("expected an error item for an invalid reference")
	}

	if findEntry(hook, logrus.ErrorLevel, "!invalid!") == nil {
		t.Error("expected the invalid reference to be logged at error level")
	}
}

func TestLogVerificationResult(t *testing.T) {
	hook := test.NewLocal(logrus.StandardLogger())
	defer hook.Reset()

	res := &result{
		Succeeded: false,
		ArtifactReports: []*validationReport{
			{
				Subject:  "registry.example/app:v1",
				Artifact: "registry.example/app@sha256:deadbeef",
				Results: []*verificationResult{
					{
						VerifierName: "notation-1",
						ErrorReason:  "signature is not produced by a trusted signer",
					},
				},
			},
		},
	}
	logVerificationResult(logrus.StandardLogger(), "registry.example/app:v1", res)

	entry := findEntry(hook, logrus.InfoLevel, "registry.example/app:v1")
	if entry == nil {
		t.Fatal("expected the verification result to be logged at info level")
	}
	for _, want := range []string{"notation-1", "signature is not produced by a trusted signer", `"succeeded":false`} {
		if !strings.Contains(entry.Message, want) {
			t.Errorf("expected the logged result to contain %q, got: %s", want, entry.Message)
		}
	}
}

// A warm cache must not make the request log go quiet: the outcome is the audit
// signal, so it is reported whether or not the result was recomputed.
func TestVerify_LogsOutcomeOnCacheHit(t *testing.T) {
	hook := test.NewLocal(logrus.StandardLogger())
	defer hook.Reset()

	artifact := "ghcr.io/org/image:v1"
	srv := &server{
		getExecutor: func(_ string) *executor.ScopedExecutor { return nil },
		verifyCache: &mockResultCache{entries: map[string]*result{
			verifyKey(artifact): {Succeeded: false},
		}},
		sfGroup: new(singleflight.Group),
	}
	body := `{"request":{"keys":["` + artifact + `"]}}`
	req := httptest.NewRequest(http.MethodPost, "/verify", strings.NewReader(body))
	if err := srv.verify(context.Background(), httptest.NewRecorder(), req); err != nil {
		t.Fatalf("verify() error = %v", err)
	}

	entry := findEntry(hook, logrus.InfoLevel, artifact)
	if entry == nil {
		t.Fatal("expected a cached verification result to still be logged at info level")
	}
	if !strings.Contains(entry.Message, "succeeded=false") {
		t.Errorf("expected the violation to be greppable, got: %s", entry.Message)
	}
}

func TestLogVerificationResult_Violation(t *testing.T) {
	hook := test.NewLocal(logrus.StandardLogger())
	defer hook.Reset()

	logVerificationResult(logrus.StandardLogger(), "registry.example/app:v1", &result{Succeeded: false})

	entry := findEntry(hook, logrus.InfoLevel, "registry.example/app:v1")
	if entry == nil {
		t.Fatal("expected a violation to be logged at info level")
	}
	if !strings.Contains(entry.Message, "succeeded=false") {
		t.Errorf("expected succeeded=false in the message, got: %s", entry.Message)
	}
}

func TestLogVerificationResult_UnmarshalableReport(t *testing.T) {
	hook := test.NewLocal(logrus.StandardLogger())
	defer hook.Reset()

	// validationReport is self-referential, so a malformed upstream report can
	// contain a cycle that json.Marshal rejects. The outcome must still be logged.
	report := &validationReport{Subject: "registry.example/app:v1"}
	report.ArtifactReports = []*validationReport{report}
	logVerificationResult(logrus.StandardLogger(), "registry.example/app:v1", &result{
		ArtifactReports: []*validationReport{report},
	})

	entry := findEntry(hook, logrus.InfoLevel, "registry.example/app:v1")
	if entry == nil {
		t.Fatal("expected the outcome to be logged even when the report cannot be marshalled")
	}
	if strings.Contains(entry.Message, "report=") {
		t.Errorf("expected the fallback message without a report, got: %s", entry.Message)
	}
}
