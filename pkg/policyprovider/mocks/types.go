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

	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/executor/types"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/verifier"
)

type TestPolicyProvider struct{}

func (p *TestPolicyProvider) VerifyNeeded(_ context.Context, _ common.Reference, _ ocispecs.ReferenceDescriptor) bool {
	return true
}

func (p *TestPolicyProvider) ContinueVerifyOnFailure(_ context.Context, _ common.Reference, _ ocispecs.ReferenceDescriptor, _ types.VerifyResult) bool {
	return true
}

func (p *TestPolicyProvider) ErrorToVerifyResult(_ context.Context, subjectRefString string, _ error) types.VerifyResult {
	errorReport := verifier.VerifierResult{
		Subject:   subjectRefString,
		IsSuccess: false,
		Message:   "this a test",
	}
	reports := make([]interface{}, 0, 1)
	reports = append(reports, errorReport)
	return types.VerifyResult{IsSuccess: false, VerifierReports: reports}
}

func (p *TestPolicyProvider) OverallVerifyResult(_ context.Context, _ []interface{}) bool {
	return true
}

func (p *TestPolicyProvider) GetPolicyType(_ context.Context) string {
	return ""
}
