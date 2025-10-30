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
	"bufio"
	"bytes"
	"errors"
	"testing"

	vpb "github.com/in-toto/attestation/go/predicates/vsa/v1"
	spb "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	mockVerifierID   = "https://github.com/slsa-framework/source-actions"
	mockResourceURI  = "git+https://github.com/notaryproject/notation"
	PASSED           = "PASSED"
	SlsaSourceLevel1 = "SLSA_SOURCE_LEVEL_1"
	SlsaSourceLevel2 = "SLSA_SOURCE_LEVEL_2"
	SlsaSourceLevel3 = "SLSA_SOURCE_LEVEL_3"
	SlsaSourceLevel4 = "SLSA_SOURCE_LEVEL_4"
)

// MockVerifier for mock testing verifier
type MockVerifier struct {
	shouldSucceed   bool
	shouldReturnVSA bool
	verifierID      string
	result          string
	error           error
}

var mockVsaPred = &vpb.VerificationSummary{
	Verifier: &vpb.VerificationSummary_Verifier{
		Id: mockVerifierID,
	},
	TimeVerified:       timestamppb.Now(),
	ResourceUri:        mockResourceURI,
	Policy:             &vpb.VerificationSummary_Policy{Uri: "DEFAULT"},
	VerificationResult: PASSED,
	VerifiedLevels:     []string{SlsaSourceLevel1},
}

func (m *MockVerifier) Verify(_ string) (*verify.VerificationResult, error) {
	if m.error != nil {
		return nil, m.error
	}

	if !m.shouldSucceed {
		return nil, errors.New("verification failed")
	}

	// If shouldReturnVSA is false, return nil statement to simulate no VSA found
	if !m.shouldReturnVSA {
		return &verify.VerificationResult{
			Statement: nil,
		}, nil
	}

	predPb, err := createMockPredicate()
	if err != nil {
		return nil, err
	}

	// Update the predicate with the mock verifier's settings
	predPb.Fields["verifier"] = &structpb.Value{
		Kind: &structpb.Value_StructValue{
			StructValue: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"id": {
						Kind: &structpb.Value_StringValue{
							StringValue: m.verifierID,
						},
					},
				},
			},
		},
	}
	predPb.Fields["verificationResult"] = &structpb.Value{
		Kind: &structpb.Value_StringValue{
			StringValue: m.result,
		},
	}

	statement := &spb.Statement{
		Type:          spb.StatementTypeUri,
		PredicateType: "https://slsa.dev/verification_summary/v1",
		Predicate:     predPb,
	}

	return &verify.VerificationResult{
		Statement: statement,
	}, nil
}

// createMockBundleReader create mock BundleReader
func createMockBundleReader(lines []string) *BundleReader {
	return createMockBundleReaderWithVSA(lines, true)
}

// createMockBundleReaderWithVSA create mock BundleReader, support shouldReturnVSA setting
func createMockBundleReaderWithVSA(lines []string, shouldReturnVSA bool) *BundleReader {
	var buffer bytes.Buffer
	for _, line := range lines {
		buffer.WriteString(line + "\n")
	}

	reader := bufio.NewReader(&buffer)
	verifier := &MockVerifier{
		shouldSucceed:   true,
		shouldReturnVSA: shouldReturnVSA,
		verifierID:      mockVerifierID,
		result:          PASSED,
	}

	return NewBundleReader(reader, verifier)
}

// createStatementWithUnknownFields Create a statement containing unknown fields to test DiscardUnknown
func createStatementWithUnknownFields() *spb.Statement {
	// create a json with unknown field
	jsonWithUnknownFields := `{
		"verifier": {
			"id": "https://github.com/slsa-framework/source-actions"
		},
		"verificationResult": "PASSED",
		"unknownField1": "unknownValue1",
		"unknownField2": {
			"nestedUnknown": "nestedValue"
		},
		"activityType": "push",
		"someOtherUnknownField": 123
	}`

	// Parse JSON to structpb.Struct
	var predStruct structpb.Struct
	err := protojson.Unmarshal([]byte(jsonWithUnknownFields), &predStruct)
	if err != nil {
		predicate, _ := createMockPredicate()
		return &spb.Statement{
			PredicateType: "https://slsa.dev/verification_summary/v1",
			Predicate:     predicate,
		}
	}

	return &spb.Statement{
		PredicateType: "https://slsa.dev/verification_summary/v1",
		Predicate:     &predStruct,
	}
}

func createMockPredicate() (*structpb.Struct, error) {
	predJSON, err := protojson.Marshal(mockVsaPred)
	if err != nil {
		return nil, err
	}

	var predPb structpb.Struct
	err = protojson.Unmarshal(predJSON, &predPb)
	if err != nil {
		return nil, err
	}
	return &predPb, nil
}

func Test_getVsaFromReader(t *testing.T) {
	tests := []struct {
		name            string
		lines           []string
		shouldReturnVSA bool
		wantErr         bool
		wantVSA         bool
	}{
		{
			name:            "empty input",
			lines:           []string{},
			shouldReturnVSA: true,
			wantErr:         true,
			wantVSA:         false,
		},
		{
			name:            "single valid VSA line",
			lines:           []string{"valid-vsa-line"},
			shouldReturnVSA: true,
			wantErr:         false,
			wantVSA:         true,
		},
		{
			name:            "multiple lines with valid VSA",
			lines:           []string{"invalid-line", "valid-vsa-line", "another-line"},
			shouldReturnVSA: true,
			wantErr:         false,
			wantVSA:         true,
		},
		{
			name:            "all invalid lines",
			lines:           []string{"invalid1", "invalid2", "invalid3"},
			shouldReturnVSA: false,
			wantErr:         true,
			wantVSA:         false,
		},
		{
			name:            "empty lines",
			lines:           []string{"", "", ""},
			shouldReturnVSA: true,
			wantErr:         true,
			wantVSA:         false,
		},
		{
			name:            "lines with newlines only",
			lines:           []string{"\n", "\n", "\n"},
			shouldReturnVSA: true,
			wantErr:         true,
			wantVSA:         false,
		},
		{
			name:            "mixed empty and valid lines",
			lines:           []string{"", "valid-vsa-line", ""},
			shouldReturnVSA: true,
			wantErr:         false,
			wantVSA:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// create mock BundleReader with shouldReturnVSA setting
			reader := createMockBundleReaderWithVSA(tt.lines, tt.shouldReturnVSA)

			stmt, vsa, err := getVsaFromReader(reader, nil)

			if (err != nil) != tt.wantErr {
				t.Errorf("getVsaFromReader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Check if return vsa
			if tt.wantVSA {
				if stmt == nil || vsa == nil {
					t.Errorf("getVsaFromReader() expected VSA but got nil statement or vsa")
					return
				}

				// verify vsa content
				if vsa.GetVerifier().GetId() != "https://github.com/slsa-framework/source-actions" {
					t.Errorf("getVsaFromReader() got verifier ID = %v, want %v",
						vsa.GetVerifier().GetId(), "https://github.com/slsa-framework/source-actions")
				}

				if vsa.GetVerificationResult() != "PASSED" {
					t.Errorf("getVsaFromReader() got verification result = %v, want %v",
						vsa.GetVerificationResult(), "PASSED")
				}
			} else {
				if stmt != nil || vsa != nil {
					t.Errorf("getVsaFromReader() expected nil but got statement or vsa")
				}
			}
		})
	}
}

func Test_getVsaFromReader_WithMaxIterations(t *testing.T) {
	// Test maximum iteration limit
	lines := make([]string, 1001) //Exceeded maximum iteration count of 1000

	for i := 0; i < 1001; i++ {
		lines[i] = "test-line"
	}

	// Create a verifier that does not return VSA to test the maximum iteration limit
	reader := createMockBundleReaderWithVSA(lines, false)
	stmt, vsa, err := getVsaFromReader(reader, nil)
	if err == nil {
		t.Errorf("getVsaFromReader() expected error for too many iterations, got nil")
	}

	if stmt != nil || vsa != nil {
		t.Errorf("getVsaFromReader() expected nil for too many iterations")
	}
}

func Test_getVsaPred(t *testing.T) {
	predPb, _ := createMockPredicate()
	tests := []struct {
		name    string
		stmt    *spb.Statement
		wantErr bool
	}{
		{
			name: "valid VSA statement",
			stmt: &spb.Statement{
				PredicateType: "https://slsa.dev/verification_summary/v1",
				Predicate:     predPb,
			},
			wantErr: false,
		},
		{
			name:    "nil statement",
			stmt:    nil,
			wantErr: true,
		},
		{
			name:    "statement with unknown fields",
			stmt:    createStatementWithUnknownFields(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getVsaPred(tt.stmt)
			if (err != nil) != tt.wantErr {
				t.Errorf("getVsaPred() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && got == nil {
				t.Errorf("getVsaPred() expected non-nil result, got nil")
			}
		})
	}
}

func TestGetVsa(t *testing.T) {
	tests := []struct {
		name            string
		attestationData []byte
		shouldReturnVSA bool
		wantErr         bool
	}{
		{
			name:            "empty data",
			attestationData: []byte{},
			shouldReturnVSA: true,
			wantErr:         true,
		},
		{
			name:            "valid attestation data",
			attestationData: []byte("valid-attestation-data"),
			shouldReturnVSA: true,
			wantErr:         false,
		},
		{
			name:            "data too large",
			attestationData: make([]byte, 101*1024*1024), // 101MB, exceeds 100MB limit
			shouldReturnVSA: true,
			wantErr:         true,
		},
		{
			name:            "data at limit",
			attestationData: make([]byte, 100*1024*1024), // 100MB, at the limit
			shouldReturnVSA: true,
			wantErr:         true,
		},
		{
			name:            "no VSA found",
			attestationData: []byte("valid-attestation-data"),
			shouldReturnVSA: false,
			wantErr:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := &MockVerifier{
				shouldSucceed:   true,
				shouldReturnVSA: tt.shouldReturnVSA,
				verifierID:      "https://github.com/slsa-framework/source-actions",
				result:          "PASSED",
			}

			stmt, vsa, err := GetVsa(tt.attestationData, verifier, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetVsa() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && (stmt == nil || vsa == nil) {
				t.Errorf("GetVsa() expected non-nil result, got nil")
			}
		})
	}
}

func TestBundleReader_ReadStatement(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  bool
	}{
		{
			name:  "empty input",
			lines: []string{},
			want:  false,
		},
		{
			name:  "single valid line",
			lines: []string{"valid-line"},
			want:  true,
		},
		{
			name:  "multiple lines",
			lines: []string{"line1", "line2", "line3"},
			want:  true,
		},
		{
			name:  "empty lines",
			lines: []string{"", "", ""},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := createMockBundleReader(tt.lines)
			stmt, err := reader.ReadStatement(VsaPredicateType)

			if tt.want {
				if err != nil {
					t.Errorf("ReadStatement() error = %v, want nil", err)
					return
				}
				if stmt == nil {
					t.Errorf("ReadStatement() expected statement, got nil")
				}
			} else {
				if stmt != nil {
					t.Errorf("ReadStatement() expected nil, got statement")
				}
			}
		})
	}
}

func Test_getVsaFromReader_WithDifferentVerifierIDs(t *testing.T) {
	tests := []struct {
		name       string
		verifierID string
		expectVSA  bool
	}{
		{
			name:       "correct verifier ID",
			verifierID: mockVerifierID,
			expectVSA:  true,
		},
		{
			name:       "wrong verifier ID",
			verifierID: "https://github.com/wrong-verifier",
			expectVSA:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := &MockVerifier{
				shouldSucceed:   true,
				shouldReturnVSA: true,
				verifierID:      mockVerifierID, // Always return the default verifier ID
				result:          PASSED,
			}

			// Create BundleReader
			var buffer bytes.Buffer
			buffer.WriteString("test-line\n")
			reader := bufio.NewReader(&buffer)
			bundleReader := NewBundleReader(reader, verifier)

			stmt, vsa, err := getVsaFromReader(bundleReader, GenerateVsaVerificationOptions(tt.verifierID, "", nil))

			if tt.expectVSA {
				if err != nil {
					t.Errorf("getVsaFromReader() error = %v", err)
					return
				}
				if stmt == nil || vsa == nil {
					t.Errorf("getVsaFromReader() expected VSA but got nil")
					return
				}
				if vsa.GetVerifier().GetId() != tt.verifierID {
					t.Errorf("getVsaFromReader() got verifier ID = %v, want %v",
						vsa.GetVerifier().GetId(), tt.verifierID)
				}
			} else {
				if err == nil {
					t.Errorf("getVsaFromReader() expected error but got nil")
				}
				if stmt != nil || vsa != nil {
					t.Errorf("getVsaFromReader() expected nil but got statement or vsa")
				}
			}
		})
	}
}

func Test_getVsaFromReader_WithDifferentResults(t *testing.T) {
	tests := []struct {
		name      string
		result    string
		expectVSA bool
	}{
		{
			name:      "PASSED result",
			result:    PASSED,
			expectVSA: true,
		},
		{
			name:      "FAILED result",
			result:    "FAILED",
			expectVSA: false,
		},
		{
			name:      "UNKNOWN result",
			result:    "UNKNOWN",
			expectVSA: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := &MockVerifier{
				shouldSucceed:   true,
				shouldReturnVSA: true,
				verifierID:      mockVerifierID,
				result:          tt.result,
			}

			// create BundleReader
			var buffer bytes.Buffer
			buffer.WriteString("test-line\n")
			reader := bufio.NewReader(&buffer)
			bundleReader := NewBundleReader(reader, verifier)

			// Use verification options to check verification result
			stmt, vsa, err := getVsaFromReader(bundleReader, GenerateVsaVerificationOptions(mockVerifierID, "", nil))

			if tt.expectVSA {
				if err != nil {
					t.Errorf("getVsaFromReader() error = %v", err)
					return
				}
				if stmt == nil || vsa == nil {
					t.Errorf("getVsaFromReader() expected VSA but got nil")
					return
				}
				if vsa.GetVerificationResult() != tt.result {
					t.Errorf("getVsaFromReader() got result = %v, want %v",
						vsa.GetVerificationResult(), tt.result)
				}
			} else {
				if err == nil {
					t.Errorf("getVsaFromReader() expected error but got nil")
				}
				if stmt != nil || vsa != nil {
					t.Errorf("getVsaFromReader() expected nil but got statement %v or vsa %v", stmt, vsa)
				}
			}
		})
	}
}
