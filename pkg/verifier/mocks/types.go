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

package mocks

import (
	"context"
	"time"

	"github.com/notaryproject/ratify/v2/pkg/executor"
	"github.com/notaryproject/ratify/v2/pkg/executor/types"
	"github.com/notaryproject/ratify/v2/pkg/verifier"
)

type TestExecutor struct {
	VerifySuccess bool
}

func (s *TestExecutor) VerifySubject(_ context.Context, _ executor.VerifyParameters) (types.VerifyResult, error) {
	report := verifier.VerifierResult{IsSuccess: s.VerifySuccess}
	return types.VerifyResult{
		IsSuccess:       s.VerifySuccess,
		VerifierReports: []interface{}{report}}, nil
}

func (s *TestExecutor) GetVerifyRequestTimeout() time.Duration {
	return 3 * time.Second
}

func (s *TestExecutor) GetMutationRequestTimeout() time.Duration {
	return 1 * time.Second
}
