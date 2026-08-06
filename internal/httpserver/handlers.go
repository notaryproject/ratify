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
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/notaryproject/ratify/v2/pkg/metrics"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/sirupsen/logrus"
	"oras.land/oras-go/v2/registry"
)

// verify handles the verification request from Gatekeeper.
func (s *server) verify(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	start := time.Now()
	defer func() { metrics.ReportVerificationRequest(ctx, time.Since(start).Milliseconds()) }()
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}

	var providerRequest externaldata.ProviderRequest
	if err = json.Unmarshal(body, &providerRequest); err != nil {
		return fmt.Errorf("failed to unmarshal request body to provider request: %w", err)
	}

	results := make([]externaldata.Item, len(providerRequest.Request.Keys))
	for idx, artifact := range providerRequest.Request.Keys {
		results[idx] = externaldata.Item{
			Key: artifact,
		}
		key := verifyKey(artifact)

		// Fetch the cache value first.
		result, err := s.verifyCache.Get(ctx, key)
		if err == nil && result != nil {
			results[idx].Value = result
			continue
		}

		// Cache is missed, block multiple goroutines from validating the same
		// artifact.
		val, err, _ := s.sfGroup.Do(key, func() (any, error) {
			executor := s.getExecutor(extractNamespace(artifact))
			if executor == nil {
				return nil, errors.New("no valid executor configured")
			}
			result, err := executor.ValidateArtifact(ctx, artifact)
			if err != nil {
				return nil, err
			}
			renderedResult := convertResult(result)
			if err = s.verifyCache.Set(ctx, key, renderedResult, 0); err != nil {
				logrus.Warnf("failed to set verify cache for image %s: %v", artifact, err)
			}
			return renderedResult, nil
		})
		if err != nil {
			results[idx].Error = err.Error()
		}
		results[idx].Value = val
	}

	return sendResponse(results, w, http.StatusOK, false)
}

// mutate handles the mutation request from Gatekeeper.
func (s *server) mutate(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	start := time.Now()
	defer func() { metrics.ReportMutationRequest(ctx, time.Since(start).Milliseconds()) }()
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}

	var providerRequest externaldata.ProviderRequest
	if err = json.Unmarshal(body, &providerRequest); err != nil {
		return fmt.Errorf("failed to unmarshal request body to provider request: %w", err)
	}
	results := make([]externaldata.Item, len(providerRequest.Request.Keys))
	for idx, key := range providerRequest.Request.Keys {
		results[idx] = s.resolveReference(ctx, key)
	}

	return sendResponse(results, w, http.StatusOK, true)
}

func (s *server) resolveReference(ctx context.Context, key string) externaldata.Item {
	namespace := extractNamespace(key)
	reference := stripNamespacePrefix(key)
	item := externaldata.Item{
		Key:   key,
		Value: reference,
	}

	ref, err := registry.ParseReference(reference)
	if err != nil {
		item.Error = fmt.Sprintf("failed to parse reference: %v", err)
		return item
	}
	if _, err = ref.Digest(); err == nil {
		item.Value = ref.String()
		return item
	}

	// Fetch the cache value first. Key on the original namespace-prefixed key so
	// that namespaces with different executor/store config do not share entries.
	cacheKey := mutateKey(key)
	result, err := s.mutateCache.Get(ctx, cacheKey)
	if err == nil && result != "" {
		item.Value = result
		return item
	}

	// Cache is missed, block multiple goroutines from resolving the same
	// reference.
	val, err, _ := s.sfGroup.Do(cacheKey, func() (any, error) {
		executor := s.getExecutor(namespace)
		if executor == nil {
			return "", errors.New("no valid executor configured")
		}
		desc, err := executor.Resolve(ctx, ref.String())
		if err != nil {
			return "", err
		}
		ref.Reference = desc.Digest.String()
		resolvedRef := ref.String()

		if err = s.mutateCache.Set(ctx, cacheKey, resolvedRef, 0); err != nil {
			logrus.Warnf("failed to set mutate cache for image %s: %v", reference, err)
		}
		return resolvedRef, nil
	})
	if err != nil {
		item.Error = err.Error()
	} else {
		item.Value = val
	}
	return item
}

func sendResponse(results []externaldata.Item, w http.ResponseWriter, respCode int, isMutation bool) error {
	response := externaldata.ProviderResponse{
		APIVersion: "externaldata.gatekeeper.sh/v1beta1",
		Kind:       "ProviderResponse",
		Response: externaldata.Response{
			Idempotent: true,
			Items:      results,
		},
	}

	// Only mutation webhook can be invoked multiple times and thus must be idempotent.
	response.Response.Idempotent = isMutation

	w.WriteHeader(respCode)
	return json.NewEncoder(w).Encode(response)
}

func mutateKey(key string) string {
	return fmt.Sprintf("%s_%s", mutatePath, key)
}

func verifyKey(key string) string {
	return fmt.Sprintf("%s_%s", verifyPath, key)
}

// extractNamespace returns the Kubernetes namespace encoded in a Gatekeeper
// external data key. Gatekeeper constraint templates prepend the workload's
// namespace as a "[namespace]" prefix to each image reference. It returns an
// empty string when no namespace prefix is present, in which case the
// cluster-scoped executor is used.
func extractNamespace(key string) string {
	if strings.HasPrefix(key, "[") {
		if idx := strings.Index(key, "]"); idx != -1 {
			return key[1:idx]
		}
	}
	return ""
}

// stripNamespacePrefix removes a leading "[namespace]" prefix from an external
// data key, returning the bare artifact reference.
func stripNamespacePrefix(key string) string {
	if strings.HasPrefix(key, "[") {
		if idx := strings.Index(key, "]"); idx != -1 {
			return key[idx+1:]
		}
	}
	return key
}
