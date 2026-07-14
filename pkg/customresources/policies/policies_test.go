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

package policies

import (
	"context"
	"testing"

	"github.com/notaryproject/ratify/v2/internal/constants"
	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/executor/types"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
)

type mockPolicy struct{}

func (p mockPolicy) VerifyNeeded(_ context.Context, _ common.Reference, _ ocispecs.ReferenceDescriptor) bool {
	return true
}

func (p mockPolicy) ContinueVerifyOnFailure(_ context.Context, _ common.Reference, _ ocispecs.ReferenceDescriptor, _ types.VerifyResult) bool {
	return true
}

func (p mockPolicy) ErrorToVerifyResult(_ context.Context, _ string, _ error) types.VerifyResult {
	return types.VerifyResult{}
}

func (p mockPolicy) OverallVerifyResult(_ context.Context, _ []interface{}) bool {
	return true
}

func (p mockPolicy) GetPolicyType(_ context.Context) string {
	return ""
}

const (
	namespace1 = constants.EmptyNamespace
	namespace2 = "namespace2"
	name1      = "name1"
	name2      = "name2"
)

var (
	policy1 = mockPolicy{}
	policy2 = mockPolicy{}
)

func TestPoliciesOperations(t *testing.T) {
	policies := NewActivePolicies()

	policies.AddPolicy(namespace1, name1, policy1)
	policies.AddPolicy(namespace2, name1, policy2)

	if policies.GetPolicy(namespace1) != policy1 {
		t.Errorf("Expected policy1 to be returned")
	}

	if policies.GetPolicy(namespace2) != policy2 {
		t.Errorf("Expected policy2 to be returned")
	}

	policies.DeletePolicy(namespace2, name1)

	if policies.GetPolicy(namespace2) != policy1 {
		t.Errorf("Expected policy1 to be returned")
	}

	policies.DeletePolicy(namespace1, name1)

	if policies.GetPolicy(namespace1) != nil {
		t.Errorf("Expected no policy to be returned")
	}
}
