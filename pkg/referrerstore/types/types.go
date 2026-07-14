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

package types

import (
	"encoding/json"
	"io"

	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
)

const (
	SpecVersion string = "0.1.0"
	Version     string = "version"
	Name        string = "name"
	Source      string = "source"
)

const (
	ErrUnknown                     uint = iota // 0
	ErrConfigParsingFailure                    // 1
	ErrInvalidStoreConfig                      // 2
	ErrUnknownCommand                          // 3
	ErrMissingEnvironmentVariables             // 4
	ErrIOFailure                               // 5
	ErrVersionNotSupported                     // 6
	ErrArgsParsingFailure                      // 7
	ErrPluginCmdFailure                        // 8
	ErrInternalFailure             uint = 999
)

// TODO Versioned Referrers result (based on the version serialize/deserialize the result)
// ReferrersResult is the result of ListReferrers as returned by the plugins
type ReferrersResult struct {
	Referrers []ocispecs.ReferenceDescriptor `json:"referrers"`
	NextToken string                         `json:"nextToken"`
}

// GetListReferrersResult unmarshall the given JSON data to list referrers result
func GetListReferrersResult(result []byte) (referrerstore.ListReferrersResult, error) {
	listResult := ReferrersResult{}
	if err := json.Unmarshal(result, &listResult); err != nil {
		return referrerstore.ListReferrersResult{}, err
	}
	return referrerstore.ListReferrersResult{
		Referrers: listResult.Referrers,
		NextToken: listResult.NextToken,
	}, nil
}

// GetReferenceManifestResult unmarshall the given JSON data to reference manifest
func GetReferenceManifestResult(result []byte) (ocispecs.ReferenceManifest, error) {
	manifest := ocispecs.ReferenceManifest{}
	if err := json.Unmarshal(result, &manifest); err != nil {
		return ocispecs.ReferenceManifest{}, err
	}
	return manifest, nil
}

// GetSubjectDescriptorResult unmarshall the given JSON data to the subject descriptor
func GetSubjectDescriptorResult(result []byte) (*ocispecs.SubjectDescriptor, error) {
	desc := ocispecs.SubjectDescriptor{}
	if err := json.Unmarshal(result, &desc); err != nil {
		return nil, err
	}
	return &desc, nil
}

// WriteListReferrersResult writes the list referrers result as JSON data to the given writer
func WriteListReferrersResult(result *referrerstore.ListReferrersResult, w io.Writer) error {
	return json.NewEncoder(w).Encode(ReferrersResult{
		Referrers: result.Referrers,
		NextToken: result.NextToken,
	})
}

// WriteReferenceManifestResult writes the reference manifest as JSON data in to the given writer
func WriteReferenceManifestResult(result *ocispecs.ReferenceManifest, w io.Writer) error {
	return json.NewEncoder(w).Encode(result)
}

// WriteSubjectDescriptorResult writes the subject descriptor as JSON data in to the given writer
func WriteSubjectDescriptorResult(result *ocispecs.SubjectDescriptor, w io.Writer) error {
	return json.NewEncoder(w).Encode(result)
}
