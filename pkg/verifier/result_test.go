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

import (
	"testing"

	e "errors"

	"github.com/notaryproject/ratify/v2/errors"
)

const (
	testMsg1        = "test message 1"
	testMsg2        = "test message 2"
	testErrReason   = "test error reason"
	testRemediation = "test remediation"
)

func TestNewVerifierResult(t *testing.T) {
	tests := []struct {
		name                string
		message             string
		err                 errors.Error
		expectedMsg         string
		expectedErrReason   string
		expectedRemediation string
	}{
		{
			name:        "nil error",
			message:     testMsg1,
			err:         errors.Error{},
			expectedMsg: testMsg1,
		},
		{
			name:                "error without detail",
			message:             testMsg1,
			err:                 errors.ErrorCodeUnknown.WithError(e.New(testErrReason)).WithRemediation(testRemediation),
			expectedMsg:         testMsg1,
			expectedErrReason:   testErrReason,
			expectedRemediation: testRemediation,
		},
		{
			name:                "error with detail",
			message:             testMsg1,
			err:                 errors.ErrorCodeUnknown.WithError(e.New(testErrReason)).WithRemediation(testRemediation).WithDetail(testMsg2),
			expectedMsg:         testMsg2,
			expectedErrReason:   testErrReason,
			expectedRemediation: testRemediation,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &tt.err
			if tt.err == (errors.Error{}) {
				err = nil
			}

			result := NewVerifierResult("", "", "", tt.message, false, err, nil)
			if result.Message != tt.expectedMsg {
				t.Errorf("expected message %s, got %s", tt.expectedMsg, result.Message)
			}
			if result.ErrorReason != tt.expectedErrReason {
				t.Errorf("expected error reason %s, got %s", tt.expectedErrReason, result.ErrorReason)
			}
			if result.Remediation != tt.expectedRemediation {
				t.Errorf("expected remediation %s, got %s", tt.expectedRemediation, result.Remediation)
			}
		})
	}
}
