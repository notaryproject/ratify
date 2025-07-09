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
		getExecutor: func() *executor.ScopedExecutor {
			return &executor.ScopedExecutor{}
		},
		verifyCache: &mockResultCache{entries: make(map[string]*result)},
		sfGroup:     new(singleflight.Group),
	}

	tests := []struct {
		name            string
		requestBody     string
		expectedError   bool
		getExecutorFunc func() *executor.ScopedExecutor
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
			getExecutorFunc: func() *executor.ScopedExecutor {
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
				getExecutor: func() *executor.ScopedExecutor {
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
