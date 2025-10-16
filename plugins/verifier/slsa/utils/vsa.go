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
	"fmt"

	vpb "github.com/in-toto/attestation/go/predicates/vsa/v1"
	spb "github.com/in-toto/attestation/go/v1"
	"github.com/ratify-project/ratify/pkg/common/plugin/logger"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	DefaultVsaVerifierID = "https://github.com/slsa-framework/source-actions"
	VsaPredicateType     = "https://slsa.dev/verification_summary/v1"
)

// Gets a VSA for the commit from git notes.
func GetVsa(attestationBytes []byte, verifier Verifier, vsaOpts *VerificationOptions) (*spb.Statement, *vpb.VerificationSummary, error) {
	return getVsaFromReader(NewBundleReader(bufio.NewReader(bytes.NewReader(attestationBytes)), verifier), vsaOpts)
}

func getVsaPred(statement *spb.Statement) (*vpb.VerificationSummary, error) {
	if statement == nil {
		return nil, fmt.Errorf("statement is nil")
	}

	predJSON, err := protojson.Marshal(statement.GetPredicate())
	if err != nil {
		return nil, err
	}

	var predStruct vpb.VerificationSummary
	unmarshaler := protojson.UnmarshalOptions{
		DiscardUnknown: true, // Ignore unknown fields to avoid parsing errors
	}
	err = unmarshaler.Unmarshal(predJSON, &predStruct)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal VSA predicate: %w", err)
	}
	return &predStruct, nil
}

func GenerateVsaVerificationOptions(expectedVerifierID, expectedResourceURI string, expectedVerifiedLevels []string) *VerificationOptions {
	if expectedVerifierID == "" {
		expectedVerifierID = DefaultVsaVerifierID
	}
	return &VerificationOptions{
		ExpectedResourceURI:    &expectedResourceURI,
		ExpectedVerifiedLevels: &expectedVerifiedLevels,
		ExpectedVerifierID:     &expectedVerifierID,
	}
}

func getVsaFromReader(reader *BundleReader, vsaOpts *VerificationOptions) (*spb.Statement, *vpb.VerificationSummary, error) {
	// We want to return the first valid VSA.
	// We should follow instructions from
	// https://slsa.dev/spec/draft/verifying-source#how-to-verify-slsa-a-source-revision

	pluginlogger := logger.NewLogger()
	maxIterations := 1000
	iterationCount := 0

	for {
		iterationCount++
		// prevent infinite loop
		if iterationCount > maxIterations {
			pluginlogger.Warnf("reached maximum iterations (%d), stopping to prevent infinite loop", maxIterations)
			return nil, nil, fmt.Errorf("too many iterations, possible infinite loop")
		}

		// Get and only process VSA type in statement
		stmt, err := reader.ReadStatement(VsaPredicateType)
		if err != nil {
			// log the error but continue retrying
			pluginlogger.Infof("error while processing line (iteration %d): %v", iterationCount, err)
			continue
		}

		if stmt == nil {
			// No statements left.
			pluginlogger.Infof("no more statements found after %d iterations", iterationCount)
			break
		}

		vsaPred, err := getVsaPred(stmt)
		if err != nil {
			pluginlogger.Infof("failed to get VSA predicate from statement: %v", err)
			continue
		}
		// check the vsaPred with expected input values
		err = matchExpectedValues(vsaPred, vsaOpts)
		if err != nil {
			return nil, nil, err
		}

		pluginlogger.Infof("found valid VSA after %d iterations", iterationCount)
		return stmt, vsaPred, nil
	}

	pluginlogger.Infof("no valid VSA found after %d iterations", iterationCount)
	return nil, nil, errors.New("no valid VSA found")
}
