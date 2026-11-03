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

package imageref

import "strings"

const (
	// defaultRegistry is the registry that container runtimes assume when an
	// image reference does not name one.
	defaultRegistry = "docker.io"

	// officialRepositoryPrefix is the namespace that Docker Hub uses for
	// official images referenced by a single path component, such as "nginx".
	officialRepositoryPrefix = "library/"
)

// Normalize expands an image reference that does not name a registry in the
// same way as container runtimes, so that Ratify verifies and resolves the
// image that is actually pulled. The first path component is treated as a
// registry only if it contains a "." or ":", is "localhost", or contains
// uppercase letters. Otherwise the reference is assumed to point to Docker Hub.
// A Docker Hub repository with a single path component also gets the
// "library/" prefix. For example:
//   - "nginx:latest" becomes "docker.io/library/nginx:latest"
//   - "org/app:v1" becomes "docker.io/org/app:v1"
//   - "docker.io/nginx" becomes "docker.io/library/nginx"
//   - "registry.example.com/app:v1" is returned unchanged
func Normalize(reference string) string {
	if reference == "" {
		return reference
	}
	domain, remainder, found := strings.Cut(reference, "/")
	if !found || (!strings.ContainsAny(domain, ".:") && domain != "localhost" && strings.ToLower(domain) == domain) {
		domain, remainder = defaultRegistry, reference
	}
	if domain == defaultRegistry && !strings.Contains(remainder, "/") {
		remainder = officialRepositoryPrefix + remainder
	}
	return domain + "/" + remainder
}
