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

package verifier

import "github.com/notaryproject/ratify/v2/errors"

// VerifierResult describes the result of verifying a reference manifest for a subject.
// Note: This struct is used to represent the result of verification in v0.
type VerifierResult struct { //nolint:revive // ignore linter to have unique type name
	Subject   string `json:"subject,omitempty"`
	IsSuccess bool   `json:"isSuccess"`
	// Name will be deprecated in v2, tracking issue: https://github.com/notaryproject/ratify/v2/issues/1707
	Name         string `json:"name,omitempty"`
	VerifierName string `json:"verifierName,omitempty"`
	// Type will be deprecated in v2, tracking issue: https://github.com/notaryproject/ratify/v2/issues/1707
	Type            string           `json:"type,omitempty"`
	VerifierType    string           `json:"verifierType,omitempty"`
	ReferenceDigest string           `json:"referenceDigest,omitempty"`
	ArtifactType    string           `json:"artifactType,omitempty"`
	Message         string           `json:"message,omitempty"`
	ErrorReason     string           `json:"errorReason,omitempty"`
	Remediation     string           `json:"remediation,omitempty"`
	Extensions      interface{}      `json:"extensions,omitempty"`
	NestedResults   []VerifierResult `json:"nestedResults,omitempty"`
}

// NewVerifierResult creates a new VerifierResult object with the given parameters.
func NewVerifierResult(subject, verifierName, verifierType, message string, isSuccess bool, err *errors.Error, extensions interface{}) VerifierResult {
	var errorReason, remediation string
	if err != nil {
		if err.GetDetail() != "" {
			message = err.GetDetail()
		}
		errorReason = err.GetErrorReason()
		remediation = err.GetRemediation()
	}
	return VerifierResult{
		Subject:      subject,
		IsSuccess:    isSuccess,
		Name:         verifierName,
		Type:         verifierType,
		VerifierName: verifierName,
		VerifierType: verifierType,
		Message:      message,
		ErrorReason:  errorReason,
		Remediation:  remediation,
		Extensions:   extensions,
	}
}
