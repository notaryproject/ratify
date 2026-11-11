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

// Package imageref normalizes image references and the scopes they are
// matched against, following the rules that container runtimes use to expand
// references that do not name a registry.
package imageref

import "strings"

const (
	// defaultRegistry is the registry that container runtimes assume when an
	// image reference does not name one.
	defaultRegistry = "docker.io"

	// officialRepositoryPrefix is the namespace that Docker Hub uses for
	// official images referenced by a single path component, such as "nginx".
	officialRepositoryPrefix = "library/"

	// localhost is treated as a registry host even though it contains neither
	// a "." nor a ":".
	localhost = "localhost"
)

// Normalize expands an image reference that does not name a registry in the
// same way as container runtimes, so that Ratify verifies and resolves the
// image that is actually pulled. The first path component is treated as a
// registry only if [IsRegistryHost] reports true for it. Otherwise the
// reference is assumed to point to Docker Hub. A Docker Hub repository with a
// single path component also gets the "library/" prefix. For example:
//   - "nginx:latest" becomes "docker.io/library/nginx:latest"
//   - "org/app:v1" becomes "docker.io/org/app:v1"
//   - "docker.io/nginx" becomes "docker.io/library/nginx"
//   - "registry.example.com/app:v1" is returned unchanged
func Normalize(reference string) string {
	if reference == "" {
		return reference
	}
	domain, remainder, found := strings.Cut(reference, "/")
	if !found || !IsRegistryHost(domain) {
		domain, remainder = defaultRegistry, reference
	}
	if domain == defaultRegistry && !strings.Contains(remainder, "/") {
		remainder = officialRepositoryPrefix + remainder
	}
	return domain + "/" + remainder
}

// NormalizeScope normalizes a repository scope, such as "docker.io/nginx" or
// "org/app", with [Normalize] so that it matches the normalized references of
// the images it covers. Registry scopes ("registry.example.com"), wildcard
// scopes ("*.example.com", "*") and the empty string are returned unchanged.
func NormalizeScope(scope string) string {
	if !strings.Contains(scope, "/") || strings.Contains(scope, "*") {
		return scope
	}
	return Normalize(scope)
}

// NormalizeScopes applies [NormalizeScope] to each scope and drops duplicates
// that normalize to the same value, keeping the order of first occurrence.
func NormalizeScopes(scopes []string) []string {
	if scopes == nil {
		return nil
	}
	normalized := make([]string, 0, len(scopes))
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		scope = NormalizeScope(scope)
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		normalized = append(normalized, scope)
	}
	return normalized
}

// IsRegistryHost reports whether the first path component of an image
// reference is treated as a registry host by container runtimes: it contains
// a "." or ":", is "localhost", or contains uppercase letters. A registry
// scope for which it reports false never matches an image, because such a
// reference is resolved on Docker Hub instead.
func IsRegistryHost(domain string) bool {
	return strings.ContainsAny(domain, ".:") || domain == localhost || strings.ToLower(domain) != domain
}
