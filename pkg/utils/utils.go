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

package utils

import (
	"fmt"
	"regexp"
	"strings"

	_ "crypto/sha256" // required package for digest.Parse

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/ratify-project/ratify/errors"
	"github.com/ratify-project/ratify/pkg/common"
)

const (
	RatifyNamespaceEnvVar = "RATIFY_NAMESPACE"
	subjectPattern        = `(\[(.*?)\])?(.*)`
)

// RequestKey is a structured external data request key.
type RequestKey struct {
	// Subject is image name in the request key.
	Subject string
	// Namespace is the scope of the image.
	Namespace string
}

// ParseDigest parses the given string and returns a validated Digest object.
func ParseDigest(digestStr string) (digest.Digest, error) {
	digest, err := digest.Parse(digestStr)
	if err != nil {
		return "", fmt.Errorf("the digest of the subject is invalid %s: %w", digestStr, err)
	}

	return digest, nil
}

// ParseSubjectReference parses the given subject and returns a valid reference
func ParseSubjectReference(subRef string) (common.Reference, error) {
	parseResult, err := reference.ParseDockerRef(subRef)
	if err != nil {
		return common.Reference{}, errors.ErrorCodeReferenceInvalid.WithDetail("failed to parse subject reference")
	}

	var subjectRef common.Reference
	if digested, ok := parseResult.(reference.Digested); ok {
		subjectRef.Digest = digested.Digest()
	}

	if tag, ok := parseResult.(reference.Tagged); ok {
		subjectRef.Tag = tag.Tag()
	}
	subjectRef.Original = parseResult.String()
	subjectRef.Path = parseResult.Name()

	return subjectRef, nil
}

// returns the string in lower case without leading and trailing space
func TrimSpaceAndToLower(input string) string {
	return strings.ToLower(strings.TrimSpace(input))
}

// ParseRequestKey parses key string to a structured RequestKey object.
// Example 1:
// key: [gatekeeper-system]docker.io/test/hello:v1
// match slice: ["[gatekeeper-system]docker.io/test/hello:v1" "[gatekeeper-system]" "gatekeeper-system" "docker.io/test/hello:v1"]
// Example 2:
// key: docker.io/test/hello:v1
// match slice: ["docker.io/test/hello:v1" "" "" "docker.io/test/hello:v1"]
func ParseRequestKey(key string) (RequestKey, error) {
	re := regexp.MustCompile(subjectPattern)
	match := re.FindStringSubmatch(key)
	if len(match) < 4 {
		return RequestKey{}, fmt.Errorf("invalid request key: %s", key)
	}
	return RequestKey{
		Namespace: match[2],
		Subject:   match[3],
	}, nil
}
