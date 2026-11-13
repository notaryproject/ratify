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

package registrystore

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	ctxUtils "github.com/notaryproject/ratify/v2/internal/context"
	"github.com/notaryproject/ratify/v2/internal/store"
)

type reportedRequest struct {
	namespace  string
	statusCode int
	host       string
}

// captureRegistryRequests swaps the metric reporter for one that records every
// call, and restores it when the test ends.
func captureRegistryRequests(t *testing.T) func() []reportedRequest {
	t.Helper()
	var (
		mu  sync.Mutex
		got []reportedRequest
	)
	orig := reportRegistryRequestCount
	reportRegistryRequestCount = func(ctx context.Context, statusCode int, registryHost string) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, reportedRequest{
			namespace:  ctxUtils.GetNamespace(ctx),
			statusCode: statusCode,
			host:       registryHost,
		})
	}
	t.Cleanup(func() { reportRegistryRequestCount = orig })
	return func() []reportedRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]reportedRequest(nil), got...)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestMetricsTransport(t *testing.T) {
	t.Run("reports the response", func(t *testing.T) {
		got := captureRegistryRequests(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer server.Close()

		ctx := ctxUtils.SetContextWithNamespace(context.Background(), "team-a")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/v2/", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		resp, err := withRequestMetrics(server.Client()).Do(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resp.Body.Close()

		want := []reportedRequest{{
			namespace:  "team-a",
			statusCode: http.StatusTooManyRequests,
			host:       strings.TrimPrefix(server.URL, "http://"),
		}}
		if reported := got(); len(reported) != 1 || reported[0] != want[0] {
			t.Errorf("reported %+v, want %+v", reported, want)
		}
	})

	t.Run("does not report a request without a response", func(t *testing.T) {
		got := captureRegistryRequests(t)
		transportErr := errors.New("connection refused")
		transport := &metricsTransport{base: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, transportErr
		})}

		req := httptest.NewRequest(http.MethodGet, "https://registry.example/v2/", nil)
		resp, err := transport.RoundTrip(req)
		if !errors.Is(err, transportErr) {
			t.Errorf("expected error %v, got %v", transportErr, err)
		}
		if resp != nil {
			t.Errorf("expected no response, got %v", resp)
		}
		if reported := got(); len(reported) != 0 {
			t.Errorf("expected no report, got %+v", reported)
		}
	})
}

func TestWithRequestMetrics(t *testing.T) {
	t.Run("default client", func(t *testing.T) {
		client := withRequestMetrics(http.DefaultClient)
		if client == http.DefaultClient {
			t.Fatal("expected a copy of the default client")
		}
		if http.DefaultClient.Transport != nil {
			t.Errorf("expected the default client to be left unchanged, got transport %T", http.DefaultClient.Transport)
		}
		transport, ok := client.Transport.(*metricsTransport)
		if !ok {
			t.Fatalf("expected *metricsTransport but got %T", client.Transport)
		}
		if transport.base != http.DefaultTransport {
			t.Errorf("expected the default transport as base, got %T", transport.base)
		}
	})

	t.Run("custom client", func(t *testing.T) {
		base := &http.Transport{}
		custom := &http.Client{Transport: base, Timeout: time.Minute}
		client := withRequestMetrics(custom)
		if custom.Transport != base {
			t.Errorf("expected the custom client to be left unchanged, got transport %T", custom.Transport)
		}
		if client.Timeout != time.Minute {
			t.Errorf("expected the timeout to be preserved, got %v", client.Timeout)
		}
		transport, ok := client.Transport.(*metricsTransport)
		if !ok {
			t.Fatalf("expected *metricsTransport but got %T", client.Transport)
		}
		if transport.base != base {
			t.Errorf("expected the custom transport as base, got %T", transport.base)
		}
	})
}

func TestRegistryStoreReportsRequests(t *testing.T) {
	got := captureRegistryRequests(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")

	s, err := store.New([]store.NewOptions{{
		Type: registryStoreType,
		Parameters: map[string]any{
			"plainHttp": true,
			"credential": map[string]any{
				"provider": "static",
				"password": "token",
			},
		},
	}}, nil)
	if err != nil {
		t.Fatalf("failed to create registry store: %v", err)
	}

	ctx := ctxUtils.SetContextWithNamespace(context.Background(), "team-a")
	if _, err := s.Resolve(ctx, host+"/test/image:v1"); err == nil {
		t.Fatal("expected an error resolving a missing manifest")
	}

	want := reportedRequest{namespace: "team-a", statusCode: http.StatusNotFound, host: host}
	reported := got()
	if len(reported) == 0 {
		t.Fatal("expected the registry request to be reported")
	}
	for _, r := range reported {
		if r != want {
			t.Errorf("reported %+v, want %+v", r, want)
		}
	}
}
