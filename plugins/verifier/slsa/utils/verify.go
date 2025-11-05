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
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/carabiner-dev/signer"
	"github.com/carabiner-dev/signer/options"
	vpb "github.com/in-toto/attestation/go/predicates/vsa/v1"
	"github.com/ratify-project/ratify/pkg/common/plugin/logger"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

type VerificationOptions struct {
	ExpectedIssuer string
	ExpectedSan    string
	// ExpectedVerifierID is the verifier ID that is passed from user.
	ExpectedVerifierID *string
	// ExpectedResourceURI is the resource URI that is passed from user.
	ExpectedResourceURI *string
	// ExpectedVerifiedLevels is the levels of verification that are passed from user.
	ExpectedVerifiedLevels *[]string
}

const (
	// ExpectedIssuer is the OIDC issuer found in the sigstore bundles
	ExpectedIssuer = "https://token.actions.githubusercontent.com"

	// Expected SAN is the expected identity of the workflow signing the
	// provenance and VSAs.
	ExpectedSan = "https://github.com/slsa-framework/source-actions/.github/workflows/compute_slsa_source.yml@refs/heads/main"

	// OldExpectedSan is the old singer identity before splitting out the actions to their own repo
	// this constant is part of a compatibility hack that should be reverted once the latests attestations
	// of the repos are signed with the new identity.
	//
	// See https://github.com/slsa-framework/source-tool/issues/255
	OldExpectedSan = "https://github.com/slsa-framework/slsa-source-poc/.github/workflows/compute_slsa_source.yml@refs/heads/main"
)

var (
	ErrorInvalidVerificationResult = errors.New("verificationResult is not PASSED")
	ErrorMismatchVerifiedLevels    = errors.New("verified levels do not match")
	ErrorEmptyRequiredField        = errors.New("empty value in required field")
	ErrorMismatchResourceURI       = errors.New("resource URI does not match")
	ErrorMismatchVerifierID        = errors.New("verifier ID does not match")
	ErrorInvalidSLSALevel          = errors.New("invalid SLSA level")
)

// TODO: Update ExpectedSan to support regex so we can get the branches/tags we really think
// folks should be using (they won't all run from main).
var DefaultVerifierOptions = VerificationOptions{
	ExpectedIssuer: ExpectedIssuer,
	ExpectedSan:    ExpectedSan,
}

type Verifier interface {
	Verify(data string) (*verify.VerificationResult, error)
}

type BndVerifier struct {
	Options VerificationOptions
	Logger  *logger.Logger
}

func (bv *BndVerifier) Verify(data string) (*verify.VerificationResult, error) {
	// TODO: There's more for us to do here... but what?
	// Maybe check to make sure it's from the identity we expect (the workflow?)
	verifier := signer.NewVerifier()

	// Verify the signed bundle
	vr, err := verifier.VerifyInlineBundle(
		[]byte(data),
		options.WithExpectedIdentity(
			bv.Options.ExpectedIssuer, bv.Options.ExpectedSan,
		),
	)
	if err != nil {
		bv.Logger.Warnf("error verifying bundle: %v", err)
		return nil, err
	}
	bv.Logger.Infof("success verified bundle with identity %s", vr.VerifiedIdentity.SourceRepositoryURI)

	return vr, nil
}

func NewBndVerifier(opts VerificationOptions) *BndVerifier {
	return &BndVerifier{Options: opts, Logger: logger.NewLogger()}
}

func GetDefaultVerifier() Verifier {
	return NewBndVerifier(DefaultVerifierOptions)
}

// matchVerifierID checks if the verifier ID in the VSA matches the expected value.
func matchVerifierID(vsa *vpb.VerificationSummary, vsaOpts *VerificationOptions) error {
	if vsa.Verifier.Id == "" {
		return fmt.Errorf("%w: no verifierID found in the VSA", ErrorEmptyRequiredField)
	}
	if vsaOpts.ExpectedVerifierID != nil && *vsaOpts.ExpectedVerifierID != vsa.Verifier.Id {
		return fmt.Errorf("%w: verifier ID mismatch: wanted %s, got %s", ErrorMismatchVerifierID, *vsaOpts.ExpectedVerifierID, vsa.Verifier.Id)
	}
	return nil
}

// matchResourceURI checks if the resource URI in the VSA matches the expected value.
func matchResourceURI(vsa *vpb.VerificationSummary, vsaOpts *VerificationOptions) error {
	if vsa.ResourceUri == "" {
		return fmt.Errorf("%w: no resourceURI provided", ErrorEmptyRequiredField)
	}
	if vsaOpts.ExpectedResourceURI != nil && *vsaOpts.ExpectedResourceURI != vsa.ResourceUri {
		return fmt.Errorf("%w: resource URI mismatch: wanted %s, got %s", ErrorMismatchResourceURI, *vsaOpts.ExpectedResourceURI, vsa.ResourceUri)
	}
	return nil
}

// confirmVerificationResult checks that the policy verification result is "PASSED".
func confirmVerificationResult(vsa *vpb.VerificationSummary) error {
	if vsa.VerificationResult != "PASSED" {
		return fmt.Errorf("%w: verification result is not Passed: %s", ErrorInvalidVerificationResult, vsa.VerificationResult)
	}
	return nil
}

// matchVerifiedLevels checks if the verified levels in the VSA match the expected values.
func matchVerifiedLevels(vsa *vpb.VerificationSummary, vsaOpts *VerificationOptions) error {
	// If no expected levels are provided, skip validation
	if vsaOpts.ExpectedVerifiedLevels == nil {
		return nil
	}

	// check for SLSA track levels
	wantedSLSALevels, err := extractSLSALevels(vsaOpts.ExpectedVerifiedLevels)
	if err != nil {
		return err
	}
	gotSLSALevels, err := extractSLSALevels(&vsa.VerifiedLevels)
	if err != nil {
		return err
	}
	for track, expectedMinLSLSALevel := range wantedSLSALevels {
		if vsaLevel, exists := gotSLSALevels[track]; !exists {
			return fmt.Errorf("%w: expected SLSA level not found: %s", ErrorMismatchVerifiedLevels, track)
		} else if vsaLevel < expectedMinLSLSALevel {
			return fmt.Errorf("%w: expected SLSA level %s to be at least %d, got %d", ErrorMismatchVerifiedLevels, track, expectedMinLSLSALevel, vsaLevel)
		}
	}

	// check for non-SLSA track levels
	nonSLSAVSALevels := make(map[string]bool)
	for _, level := range vsa.VerifiedLevels {
		if isSLSATRACKLevel(level) {
			continue
		}
		nonSLSAVSALevels[level] = true
	}
	for _, expectedLevel := range *vsaOpts.ExpectedVerifiedLevels {
		if isSLSATRACKLevel(expectedLevel) {
			continue
		}
		if _, ok := nonSLSAVSALevels[expectedLevel]; !ok {
			return fmt.Errorf("%w: expected verified level not found: %s", ErrorMismatchVerifiedLevels, expectedLevel)
		}
	}
	return nil
}

// extractSLSALevels extracts the SLSA levels from the verified levels.
// It returns a map of track to the highest level found, e.g.,
// SLSA_BUILD_LEVEL_2, SLSA_SOURCE_LEVEL_3 ->
//
//	{
//		"BUILD": 2,
//		"SOURCE": 3,
//	}
func extractSLSALevels(trackLevels *[]string) (map[string]int, error) {
	vsaSLSATrackLadder := make(map[string]int)
	if trackLevels == nil {
		return nil, fmt.Errorf("%w: track levels cannot be nil", ErrorInvalidSLSALevel)
	}
	for _, trackLevel := range *trackLevels {
		if !strings.HasPrefix(trackLevel, "SLSA_") {
			continue
		}
		parts := strings.SplitN(trackLevel, "_", 4)
		if len(parts) != 4 {
			return nil, fmt.Errorf("%w: invalid SLSA level: %s", ErrorInvalidSLSALevel, trackLevel)
		}
		if parts[2] != "LEVEL" {
			return nil, fmt.Errorf("%w: invalid SLSA level: %s", ErrorInvalidSLSALevel, trackLevel)
		}
		track := parts[1]
		level, err := strconv.Atoi(parts[3])
		if err != nil {
			return nil, fmt.Errorf("%w: invalid SLSA level: %s", ErrorInvalidSLSALevel, trackLevel)
		}
		if currentLevel, exists := vsaSLSATrackLadder[track]; exists {
			vsaSLSATrackLadder[track] = max(currentLevel, level)
		} else {
			vsaSLSATrackLadder[track] = level
		}
	}
	return vsaSLSATrackLadder, nil
}

// isSLSATRACKLevel checks if the level is an SLSA track level.
// SLSA track levels are of the form SLSA_<track>_LEVEL_<level>, e.g., SLSA_BUILD_LEVEL_2.
func isSLSATRACKLevel(level string) bool {
	return strings.HasPrefix(level, "SLSA_")
}

// matchExpectedValues checks if the expected values are present in the VSA.
func matchExpectedValues(vsa *vpb.VerificationSummary, vsaOpts *VerificationOptions) error {
	// If no options provided, skip validation
	if vsaOpts == nil {
		return nil
	}

	// match the expected verifierID
	if err := matchVerifierID(vsa, vsaOpts); err != nil {
		return err
	}
	// match the expected resourceURI
	if vsaOpts.ExpectedResourceURI != nil && *vsaOpts.ExpectedResourceURI != "" {
		if err := matchResourceURI(vsa, vsaOpts); err != nil {
			return err
		}
	}
	// confirm the verificationResult is Passed
	if err := confirmVerificationResult(vsa); err != nil {
		return err
	}
	// match the verifiedLevels
	if vsaOpts.ExpectedVerifiedLevels != nil && len(*vsaOpts.ExpectedVerifiedLevels) > 0 {
		if err := matchVerifiedLevels(vsa, vsaOpts); err != nil {
			return err
		}
	}
	return nil
}
