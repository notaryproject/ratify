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

	"github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/pkg/verifier"
)

const (
	SpecVersion      string = "0.1.0"
	Version          string = "version"
	Name             string = "name"
	Type             string = "type"
	ArtifactTypes    string = "artifactTypes"
	NestedReferences string = "nestedReferences"
	Source           string = "source"
)

const (
	ErrUnknown                     uint = iota // 0
	ErrConfigParsingFailure                    // 1
	ErrInvalidVerifierConfig                   // 2
	ErrUnknownCommand                          // 3
	ErrMissingEnvironmentVariables             // 4
	ErrIOFailure                               // 5
	ErrVersionNotSupported                     // 6
	ErrArgsParsingFailure                      // 7
	ErrPluginCmdFailure                        // 8
	ErrInternalFailure             uint = 999
)

// VerifierResult describes the verification result returned from the verifier plugin
type VerifierResult struct {
	IsSuccess   bool   `json:"isSuccess"`
	Message     string `json:"message"`
	ErrorReason string `json:"errorReason,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	// Name will be deprecated in v2, tracking issue: https://github.com/notaryproject/ratify/v2/issues/1707
	Name         string `json:"name"`
	VerifierName string `json:"verifierName,omitempty"`
	// Type will be deprecated in v2, tracking issue: https://github.com/notaryproject/ratify/v2/issues/1707
	Type         string      `json:"type,omitempty"`
	VerifierType string      `json:"verifierType,omitempty"`
	Extensions   interface{} `json:"extensions"`
}

// GetVerifierResult encodes the given JSON data into verify result object
func GetVerifierResult(result []byte) (*verifier.VerifierResult, error) {
	vResult := VerifierResult{}
	if err := json.Unmarshal(result, &vResult); err != nil {
		return nil, err
	}
	return &verifier.VerifierResult{
		IsSuccess:    vResult.IsSuccess,
		Message:      vResult.Message,
		Name:         vResult.Name,
		Type:         vResult.Type,
		VerifierName: vResult.Name,
		VerifierType: vResult.Type,
		Extensions:   vResult.Extensions,
	}, nil
}

// WriteVerifyResultResult writes the given result as JSON data to the writer w
func WriteVerifyResultResult(result *verifier.VerifierResult, w io.Writer) error {
	return json.NewEncoder(w).Encode(result)
}

// CreateVerifierResult creates a new verifier result object from given input.
func CreateVerifierResult(verifierName, verifierType, message string, isSuccess bool, err *errors.Error) VerifierResult {
	var errorReason string
	var remediation string
	if err != nil {
		if err.GetDetail() != "" {
			message = err.GetDetail()
		}
		errorReason = err.GetErrorReason()
		remediation = err.GetRemediation()
	}

	return VerifierResult{
		IsSuccess:    isSuccess,
		Name:         verifierName,
		Type:         verifierType,
		VerifierName: verifierName,
		VerifierType: verifierType,
		Message:      message,
		ErrorReason:  errorReason,
		Remediation:  remediation,
	}
}

// NewVerifierResult creates a new verifier result object from the given
// verifier.VerifierResult.
func NewVerifierResult(result verifier.VerifierResult) VerifierResult {
	return VerifierResult{
		IsSuccess:    result.IsSuccess,
		Message:      result.Message,
		Name:         result.Name,
		Type:         result.Type,
		VerifierName: result.VerifierName,
		VerifierType: result.VerifierType,
		Extensions:   result.Extensions,
		ErrorReason:  result.ErrorReason,
		Remediation:  result.Remediation,
	}
}
