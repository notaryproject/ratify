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
	"testing"

	vpb "github.com/in-toto/attestation/go/predicates/vsa/v1"
)

func TestBndVerifier_Verify(t *testing.T) {
	tests := []struct {
		name        string
		options     VerificationOptions
		data        string
		expectError bool
		description string
	}{
		//{
		//	name: "valid verification with default options",
		//	options: VerificationOptions{
		//		ExpectedIssuer: ExpectedIssuer,
		//		ExpectedSan:    ExpectedSan,
		//	},
		//	data:        "valid-bundle-data",
		//	expectError: false,
		//	description: "should work with valid bundle data",
		//},
		{
			name: "invalid issuer",
			options: VerificationOptions{
				ExpectedIssuer: "https://invalid-issuer.com",
				ExpectedSan:    ExpectedSan,
			},
			data:        "valid-bundle-data",
			expectError: true,
			description: "should fail with invalid issuer",
		},
		{
			name: "invalid SAN",
			options: VerificationOptions{
				ExpectedIssuer: ExpectedIssuer,
				ExpectedSan:    "https://invalid-san.com",
			},
			data:        "valid-bundle-data",
			expectError: true,
			description: "should fail with invalid SAN",
		},
		{
			name: "empty data",
			options: VerificationOptions{
				ExpectedIssuer: ExpectedIssuer,
				ExpectedSan:    ExpectedSan,
			},
			data:        "",
			expectError: true,
			description: "should fail with empty data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := NewBndVerifier(tt.options)
			_, err := verifier.Verify(tt.data)

			if (err != nil) != tt.expectError {
				t.Errorf("BndVerifier.Verify() error = %v, expectError %v, %s", err, tt.expectError, tt.description)
			}
		})
	}
}

func TestNewBndVerifier(t *testing.T) {
	tests := []struct {
		name    string
		options VerificationOptions
		want    *BndVerifier
	}{
		{
			name: "create verifier with default options",
			options: VerificationOptions{
				ExpectedIssuer: ExpectedIssuer,
				ExpectedSan:    ExpectedSan,
			},
			want: &BndVerifier{
				Options: VerificationOptions{
					ExpectedIssuer: ExpectedIssuer,
					ExpectedSan:    ExpectedSan,
				},
			},
		},
		{
			name: "create verifier with custom options",
			options: VerificationOptions{
				ExpectedIssuer: "https://custom-issuer.com",
				ExpectedSan:    "https://custom-san.com",
			},
			want: &BndVerifier{
				Options: VerificationOptions{
					ExpectedIssuer: "https://custom-issuer.com",
					ExpectedSan:    "https://custom-san.com",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewBndVerifier(tt.options)
			if got.Options.ExpectedIssuer != tt.want.Options.ExpectedIssuer {
				t.Errorf("NewBndVerifier() ExpectedIssuer = %v, want %v", got.Options.ExpectedIssuer, tt.want.Options.ExpectedIssuer)
			}
			if got.Options.ExpectedSan != tt.want.Options.ExpectedSan {
				t.Errorf("NewBndVerifier() ExpectedSan = %v, want %v", got.Options.ExpectedSan, tt.want.Options.ExpectedSan)
			}
		})
	}
}

func TestGetDefaultVerifier(t *testing.T) {
	verifier := GetDefaultVerifier()

	if verifier == nil {
		t.Errorf("GetDefaultVerifier() returned nil")
		return
	}

	bndVerifier, ok := verifier.(*BndVerifier)
	if !ok {
		t.Errorf("GetDefaultVerifier() returned wrong type")
		return
	}

	if bndVerifier.Options.ExpectedIssuer != ExpectedIssuer {
		t.Errorf("GetDefaultVerifier() ExpectedIssuer = %v, want %v", bndVerifier.Options.ExpectedIssuer, ExpectedIssuer)
	}
	if bndVerifier.Options.ExpectedSan != ExpectedSan {
		t.Errorf("GetDefaultVerifier() ExpectedSan = %v, want %v", bndVerifier.Options.ExpectedSan, ExpectedSan)
	}
}

func Test_matchVerifierID(t *testing.T) {
	const testVerifierID = "https://github.com/slsa-framework/source-actions"
	expectedVerifierID := testVerifierID

	tests := []struct {
		name    string
		vsa     *vpb.VerificationSummary
		vsaOpts *VerificationOptions
		wantErr bool
	}{
		{
			name: "matching verifier ID",
			vsa: &vpb.VerificationSummary{
				Verifier: &vpb.VerificationSummary_Verifier{
					Id: expectedVerifierID,
				},
			},
			vsaOpts: &VerificationOptions{
				ExpectedVerifierID: &expectedVerifierID,
			},
			wantErr: false,
		},
		{
			name: "mismatched verifier ID",
			vsa: &vpb.VerificationSummary{
				Verifier: &vpb.VerificationSummary_Verifier{
					Id: "https://github.com/wrong-verifier",
				},
			},
			vsaOpts: &VerificationOptions{
				ExpectedVerifierID: &expectedVerifierID,
			},
			wantErr: true,
		},
		{
			name: "empty verifier ID",
			vsa: &vpb.VerificationSummary{
				Verifier: &vpb.VerificationSummary_Verifier{
					Id: "",
				},
			},
			vsaOpts: &VerificationOptions{
				ExpectedVerifierID: &expectedVerifierID,
			},
			wantErr: true,
		},
		{
			name: "nil expected verifier ID",
			vsa: &vpb.VerificationSummary{
				Verifier: &vpb.VerificationSummary_Verifier{
					Id: expectedVerifierID,
				},
			},
			vsaOpts: &VerificationOptions{
				ExpectedVerifierID: nil,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := matchVerifierID(tt.vsa, tt.vsaOpts)
			if (err != nil) != tt.wantErr {
				t.Errorf("matchVerifierID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_matchResourceURI(t *testing.T) {
	expectedResourceURI := "git+https://github.com/test/repo"

	tests := []struct {
		name    string
		vsa     *vpb.VerificationSummary
		vsaOpts *VerificationOptions
		wantErr bool
	}{
		{
			name: "matching resource URI",
			vsa: &vpb.VerificationSummary{
				ResourceUri: expectedResourceURI,
			},
			vsaOpts: &VerificationOptions{
				ExpectedResourceURI: &expectedResourceURI,
			},
			wantErr: false,
		},
		{
			name: "mismatched resource URI",
			vsa: &vpb.VerificationSummary{
				ResourceUri: "git+https://github.com/wrong/repo",
			},
			vsaOpts: &VerificationOptions{
				ExpectedResourceURI: &expectedResourceURI,
			},
			wantErr: true,
		},
		{
			name: "empty resource URI",
			vsa: &vpb.VerificationSummary{
				ResourceUri: "",
			},
			vsaOpts: &VerificationOptions{
				ExpectedResourceURI: &expectedResourceURI,
			},
			wantErr: true,
		},
		{
			name: "nil expected resource URI",
			vsa: &vpb.VerificationSummary{
				ResourceUri: expectedResourceURI,
			},
			vsaOpts: &VerificationOptions{
				ExpectedResourceURI: nil,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := matchResourceURI(tt.vsa, tt.vsaOpts)
			if (err != nil) != tt.wantErr {
				t.Errorf("matchResourceURI() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_confirmVerificationResult(t *testing.T) {
	tests := []struct {
		name    string
		vsa     *vpb.VerificationSummary
		wantErr bool
	}{
		{
			name: "PASSED result",
			vsa: &vpb.VerificationSummary{
				VerificationResult: "PASSED",
			},
			wantErr: false,
		},
		{
			name: "FAILED result",
			vsa: &vpb.VerificationSummary{
				VerificationResult: "FAILED",
			},
			wantErr: true,
		},
		{
			name: "UNKNOWN result",
			vsa: &vpb.VerificationSummary{
				VerificationResult: "UNKNOWN",
			},
			wantErr: true,
		},
		{
			name: "empty result",
			vsa: &vpb.VerificationSummary{
				VerificationResult: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := confirmVerificationResult(tt.vsa)
			if (err != nil) != tt.wantErr {
				t.Errorf("confirmVerificationResult() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_extractSLSALevels(t *testing.T) {
	tests := []struct {
		name        string
		trackLevels *[]string
		want        map[string]int
		wantErr     bool
	}{
		{
			name:        "valid SLSA levels",
			trackLevels: &[]string{"SLSA_BUILD_LEVEL_2", "SLSA_SOURCE_LEVEL_3", "SLSA_PROVENANCE_LEVEL_1"},
			want: map[string]int{
				"BUILD":      2,
				"SOURCE":     3,
				"PROVENANCE": 1,
			},
			wantErr: false,
		},
		{
			name:        "mixed levels with non-SLSA",
			trackLevels: &[]string{"SLSA_BUILD_LEVEL_2", "CUSTOM_LEVEL_1", "SLSA_SOURCE_LEVEL_3"},
			want: map[string]int{
				"BUILD":  2,
				"SOURCE": 3,
			},
			wantErr: false,
		},
		{
			name:        "duplicate levels with higher value",
			trackLevels: &[]string{"SLSA_BUILD_LEVEL_2", "SLSA_BUILD_LEVEL_3"},
			want: map[string]int{
				"BUILD": 3,
			},
			wantErr: false,
		},
		{
			name:        "invalid SLSA level format",
			trackLevels: &[]string{"SLSA_BUILD_INVALID_2"},
			want:        nil,
			wantErr:     true,
		},
		{
			name:        "invalid SLSA level number",
			trackLevels: &[]string{"SLSA_BUILD_LEVEL_INVALID"},
			want:        nil,
			wantErr:     true,
		},
		{
			name:        "empty levels",
			trackLevels: &[]string{},
			want:        map[string]int{},
			wantErr:     false,
		},
		{
			name:        "nil levels",
			trackLevels: nil,
			want:        nil,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractSLSALevels(tt.trackLevels)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractSLSALevels() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !compareMaps(got, tt.want) {
				t.Errorf("extractSLSALevels() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isSLSATRACKLevel(t *testing.T) {
	tests := []struct {
		name  string
		level string
		want  bool
	}{
		{
			name:  "SLSA track level",
			level: "SLSA_BUILD_LEVEL_2",
			want:  true,
		},
		{
			name:  "SLSA source level",
			level: "SLSA_SOURCE_LEVEL_3",
			want:  true,
		},
		{
			name:  "non-SLSA level",
			level: "CUSTOM_LEVEL_1",
			want:  false,
		},
		{
			name:  "empty level",
			level: "",
			want:  false,
		},
		{
			name:  "SLSA prefix but not track level",
			level: "SLSA_CUSTOM",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSLSATRACKLevel(tt.level)
			if got != tt.want {
				t.Errorf("isSLSATRACKLevel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_matchVerifiedLevels(t *testing.T) {
	expectedLevels := []string{"SLSA_BUILD_LEVEL_2", "SLSA_SOURCE_LEVEL_3", "CUSTOM_LEVEL_1"}

	tests := []struct {
		name    string
		vsa     *vpb.VerificationSummary
		vsaOpts *VerificationOptions
		wantErr bool
	}{
		{
			name: "matching verified levels",
			vsa: &vpb.VerificationSummary{
				VerifiedLevels: []string{"SLSA_BUILD_LEVEL_2", "SLSA_SOURCE_LEVEL_3", "CUSTOM_LEVEL_1"},
			},
			vsaOpts: &VerificationOptions{
				ExpectedVerifiedLevels: &expectedLevels,
			},
			wantErr: false,
		},
		{
			name: "higher SLSA levels",
			vsa: &vpb.VerificationSummary{
				VerifiedLevels: []string{"SLSA_BUILD_LEVEL_3", "SLSA_SOURCE_LEVEL_4", "CUSTOM_LEVEL_1"},
			},
			vsaOpts: &VerificationOptions{
				ExpectedVerifiedLevels: &expectedLevels,
			},
			wantErr: false,
		},
		{
			name: "lower SLSA levels",
			vsa: &vpb.VerificationSummary{
				VerifiedLevels: []string{"SLSA_BUILD_LEVEL_1", "SLSA_SOURCE_LEVEL_2", "CUSTOM_LEVEL_1"},
			},
			vsaOpts: &VerificationOptions{
				ExpectedVerifiedLevels: &expectedLevels,
			},
			wantErr: true,
		},
		{
			name: "missing non-SLSA level",
			vsa: &vpb.VerificationSummary{
				VerifiedLevels: []string{"SLSA_BUILD_LEVEL_2", "SLSA_SOURCE_LEVEL_3"},
			},
			vsaOpts: &VerificationOptions{
				ExpectedVerifiedLevels: &expectedLevels,
			},
			wantErr: true,
		},
		{
			name: "missing SLSA level",
			vsa: &vpb.VerificationSummary{
				VerifiedLevels: []string{"SLSA_BUILD_LEVEL_2", "CUSTOM_LEVEL_1"},
			},
			vsaOpts: &VerificationOptions{
				ExpectedVerifiedLevels: &expectedLevels,
			},
			wantErr: true,
		},
		{
			name: "nil expected levels",
			vsa: &vpb.VerificationSummary{
				VerifiedLevels: []string{"SLSA_BUILD_LEVEL_2"},
			},
			vsaOpts: &VerificationOptions{
				ExpectedVerifiedLevels: nil,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := matchVerifiedLevels(tt.vsa, tt.vsaOpts)
			if (err != nil) != tt.wantErr {
				t.Errorf("matchVerifiedLevels() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_matchExpectedValues(t *testing.T) {
	const testVerifierID = "https://github.com/slsa-framework/source-actions"
	expectedVerifierID := testVerifierID
	expectedResourceURI := "git+https://github.com/test/repo"
	expectedLevels := []string{"SLSA_BUILD_LEVEL_2"}

	tests := []struct {
		name    string
		vsa     *vpb.VerificationSummary
		vsaOpts *VerificationOptions
		wantErr bool
	}{
		{
			name: "all values match",
			vsa: &vpb.VerificationSummary{
				Verifier: &vpb.VerificationSummary_Verifier{
					Id: expectedVerifierID,
				},
				ResourceUri:        expectedResourceURI,
				VerificationResult: "PASSED",
				VerifiedLevels:     []string{"SLSA_BUILD_LEVEL_2"},
			},
			vsaOpts: &VerificationOptions{
				ExpectedVerifierID:     &expectedVerifierID,
				ExpectedResourceURI:    &expectedResourceURI,
				ExpectedVerifiedLevels: &expectedLevels,
			},
			wantErr: false,
		},
		{
			name: "verifier ID mismatch",
			vsa: &vpb.VerificationSummary{
				Verifier: &vpb.VerificationSummary_Verifier{
					Id: "https://github.com/wrong-verifier",
				},
				ResourceUri:        expectedResourceURI,
				VerificationResult: "PASSED",
				VerifiedLevels:     []string{"SLSA_BUILD_LEVEL_2"},
			},
			vsaOpts: &VerificationOptions{
				ExpectedVerifierID:     &expectedVerifierID,
				ExpectedResourceURI:    &expectedResourceURI,
				ExpectedVerifiedLevels: &expectedLevels,
			},
			wantErr: true,
		},
		{
			name: "resource URI mismatch",
			vsa: &vpb.VerificationSummary{
				Verifier: &vpb.VerificationSummary_Verifier{
					Id: expectedVerifierID,
				},
				ResourceUri:        "git+https://github.com/wrong/repo",
				VerificationResult: "PASSED",
				VerifiedLevels:     []string{"SLSA_BUILD_LEVEL_2"},
			},
			vsaOpts: &VerificationOptions{
				ExpectedVerifierID:     &expectedVerifierID,
				ExpectedResourceURI:    &expectedResourceURI,
				ExpectedVerifiedLevels: &expectedLevels,
			},
			wantErr: true,
		},
		{
			name: "verification result not PASSED",
			vsa: &vpb.VerificationSummary{
				Verifier: &vpb.VerificationSummary_Verifier{
					Id: expectedVerifierID,
				},
				ResourceUri:        expectedResourceURI,
				VerificationResult: "FAILED",
				VerifiedLevels:     []string{"SLSA_BUILD_LEVEL_2"},
			},
			vsaOpts: &VerificationOptions{
				ExpectedVerifierID:     &expectedVerifierID,
				ExpectedResourceURI:    &expectedResourceURI,
				ExpectedVerifiedLevels: &expectedLevels,
			},
			wantErr: true,
		},
		{
			name: "verified levels mismatch",
			vsa: &vpb.VerificationSummary{
				Verifier: &vpb.VerificationSummary_Verifier{
					Id: expectedVerifierID,
				},
				ResourceUri:        expectedResourceURI,
				VerificationResult: "PASSED",
				VerifiedLevels:     []string{"SLSA_BUILD_LEVEL_1"},
			},
			vsaOpts: &VerificationOptions{
				ExpectedVerifierID:     &expectedVerifierID,
				ExpectedResourceURI:    &expectedResourceURI,
				ExpectedVerifiedLevels: &expectedLevels,
			},
			wantErr: true,
		},
		{
			name: "nil options",
			vsa: &vpb.VerificationSummary{
				Verifier: &vpb.VerificationSummary_Verifier{
					Id: expectedVerifierID,
				},
				ResourceUri:        expectedResourceURI,
				VerificationResult: "PASSED",
				VerifiedLevels:     []string{"SLSA_BUILD_LEVEL_2"},
			},
			vsaOpts: &VerificationOptions{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := matchExpectedValues(tt.vsa, tt.vsaOpts)
			if (err != nil) != tt.wantErr {
				t.Errorf("matchExpectedValues() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Helper function to compare maps
func compareMaps(map1, map2 map[string]int) bool {
	if len(map1) != len(map2) {
		return false
	}
	for key, value := range map1 {
		if map2[key] != value {
			return false
		}
	}
	return true
}
