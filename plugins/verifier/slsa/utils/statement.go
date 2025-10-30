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
	"errors"
	"fmt"
	"io"
	"strings"

	spb "github.com/in-toto/attestation/go/v1"
	"github.com/ratify-project/ratify/pkg/common/plugin/logger"
)

const (
	maxLines      = 10000       // The max statement line to prevent infinite loop
	limitLineSize = 1024 * 1024 // 1MB per statement line limit
)

type BundleReader struct {
	reader   *bufio.Reader
	verifier Verifier
}

func NewBundleReader(reader *bufio.Reader, verifier Verifier) *BundleReader {
	return &BundleReader{reader: reader, verifier: verifier}
}

func (br *BundleReader) convertLineToStatement(line string, logger *logger.Logger) (*spb.Statement, error) {
	// Is this a sigstore bundle with a statement?
	// Verify will check the signature, but nothing else.
	vr, err := br.verifier.Verify(line)
	if err == nil {
		// This is it.
		return vr.Statement, nil
	}

	// Compatibility hack bridging identities for repository migration
	// See here for more info and when to drop:
	//
	//  https://github.com/slsa-framework/source-tool/issues/255
	if strings.Contains(err.Error(), "no matching CertificateIdentity") && strings.Contains(err.Error(), OldExpectedSan) {
		ver, err := (&BndVerifier{
			Options: VerificationOptions{
				ExpectedIssuer: ExpectedIssuer,
				ExpectedSan:    OldExpectedSan,
			},
			Logger: logger,
		}).Verify(line)
		if err == nil {
			logger.Infof("found statement signed with old identity")
			return ver.Statement, nil
		}
	}

	logger.Infof("Line '%s' failed verification: %v", line, err)

	// TODO: add support for 'regular' DSSEs.

	return nil, fmt.Errorf("could not convert line to statement: '%s': %w", line, err)
}

// Reads all the statements that:
// 1. Have a valid signature
// 2. Have the specified predicate type.
// 3. Have a subject that matches the specified git commit.
func (br *BundleReader) ReadStatement(predicateType string) (*spb.Statement, error) {
	pluginlogger := logger.NewLogger()
	// Read until we get a statement or end of file.
	lineCount := 0

	for {
		lineCount++

		// Prevent infinite loop
		if lineCount > maxLines {
			pluginlogger.Warnf("reached maximum lines (%d), stopping to prevent infinite loop", maxLines)
			return nil, fmt.Errorf("too many lines processed, possible infinite loop")
		}

		line, err := br.reader.ReadString('\n')
		if err != nil {
			// Handle end of file gracefully
			if !errors.Is(err, io.EOF) {
				return nil, err
			}
			if line == "" {
				// Nothing to see here.
				pluginlogger.Infof("reached end of file after processing %d lines", lineCount)
				break
			}
		}
		if line == "\n" {
			// skip empties
			continue
		}

		if len(line) > limitLineSize {
			pluginlogger.Warnf("skipping very long line (%d bytes), may cause memory issues", len(line))
			continue
		}

		statement, err := br.convertLineToStatement(line, pluginlogger)
		if err != nil {
			// Ignore errors, the next line could be fine.
			pluginlogger.Infof("problem converting line to statement (line %d): '%s', error: %v", lineCount, line, err)
			continue
		}
		if statement == nil {
			continue
		}

		// only process specific predicate type
		if predicateType != "" && statement.GetPredicateType() != predicateType {
			pluginlogger.Debugf("skipping statement without predicate type: %s", predicateType)
			continue
		}

		pluginlogger.Infof("successfully converted line %d to statement", lineCount)
		return statement, nil
	}

	pluginlogger.Infof("no valid statement found after processing %d lines", lineCount)
	return nil, nil
}
