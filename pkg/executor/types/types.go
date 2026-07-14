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
	"fmt"

	"github.com/notaryproject/ratify/v2/pkg/verifier/types"
)

// VerifyResult describes the results of verifying a subject
type VerifyResult struct {
	IsSuccess       bool          `json:"isSuccess,omitempty"`
	VerifierReports []interface{} `json:"verifierReports"`
}

// NestedVerifierReport describes the results of verifying an artifact and its
// nested artifacts by available verifiers.
// Note: NestedVerifierReport is used for verification results in v1.
type NestedVerifierReport struct {
	Subject         string                 `json:"subject"`
	ReferenceDigest string                 `json:"referenceDigest"`
	ArtifactType    string                 `json:"artifactType"`
	VerifierReports []types.VerifierResult `json:"verifierReports"`
	NestedReports   []NestedVerifierReport `json:"nestedReports"`
}

// NewNestedVerifierReport creates a new NestedVerifierReport from an interface.
func NewNestedVerifierReport(report interface{}) (NestedVerifierReport, error) {
	if nvr, ok := report.(NestedVerifierReport); ok {
		return nvr, nil
	}
	return NestedVerifierReport{}, fmt.Errorf("unable to convert %v to NestedVerifierReport", report)
}
