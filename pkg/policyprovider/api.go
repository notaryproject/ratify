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

package policyprovider

import (
	"context"

	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/executor/types"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
)

// PolicyProvider is an interface with methods that represents policy decisions.
type PolicyProvider interface {
	// VerifyNeeded determines if the given reference needs verification
	VerifyNeeded(ctx context.Context, subjectReference common.Reference, referenceDesc ocispecs.ReferenceDescriptor) bool
	// ContinueVerifyOnFailure determines if the given error can be ignored and verification can be continued.
	ContinueVerifyOnFailure(ctx context.Context, subjectReference common.Reference, referenceDesc ocispecs.ReferenceDescriptor, partialVerifyResult types.VerifyResult) bool
	// ErrorToVerifyResult converts an error to a properly formatted verify result
	ErrorToVerifyResult(ctx context.Context, subjectRefString string, verifyError error) types.VerifyResult
	// OverallVerifyResult determines the final outcome of verification that is constructed using the results from
	// individual verifications
	OverallVerifyResult(ctx context.Context, verifierReports []interface{}) bool
	// GetPolicyType returns the type of the policy.
	GetPolicyType(ctx context.Context) string
}
