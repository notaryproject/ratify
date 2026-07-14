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

package regopolicy

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/executor/types"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/policyprovider/config"
)

const (
	policy1 = `
package ratify.policy

default valid := false

valid {
    input.method == "GET"
}
`
	policy2 = "package"
)

type policyEngine struct {
	ReturnErr bool
}

func (e policyEngine) Evaluate(_ context.Context, _ map[string]interface{}) (bool, error) {
	if e.ReturnErr {
		return false, errors.New("error")
	}
	return true, nil
}

func TestCreate(t *testing.T) {
	factory := &Factory{}
	testCases := []struct {
		name      string
		config    config.PolicyPluginConfig
		expectErr bool
	}{
		{
			name: "invalid config",
			config: map[string]interface{}{
				"name": make(chan int),
			},
			expectErr: true,
		},
		{
			name:      "empty config",
			config:    map[string]interface{}{},
			expectErr: true,
		},
		{
			name: "config with invalid field",
			config: map[string]interface{}{
				"name":               "test",
				"passthroughEnabled": "test",
			},
			expectErr: true,
		},
		{
			name: "config with invalid policy",
			config: map[string]interface{}{
				"name":   "test",
				"policy": policy2,
			},
			expectErr: true,
		},
		{
			name: "config with valid policy",
			config: map[string]interface{}{
				"name":   "test",
				"policy": policy1,
			},
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := factory.Create(tc.config)
			if tc.expectErr != (err != nil) {
				t.Fatalf("error = %v, expectErr = %v", err, tc.expectErr)
			}
		})
	}
}

func TestVerifyNeeded(t *testing.T) {
	policyEnforcer := &policyEnforcer{
		Policy:    "",
		OpaEngine: policyEngine{},
	}
	result := policyEnforcer.VerifyNeeded(context.Background(), common.Reference{}, ocispecs.ReferenceDescriptor{})
	if result != true {
		t.Fatalf("result = %v, expectResult = %v", result, true)
	}
}

func TestContinueVerifyOnFailure(t *testing.T) {
	policyEnforcer := &policyEnforcer{
		Policy:    "",
		OpaEngine: policyEngine{},
	}
	result := policyEnforcer.ContinueVerifyOnFailure(context.Background(), common.Reference{}, ocispecs.ReferenceDescriptor{}, types.VerifyResult{})

	if !result {
		t.Fatalf("result = %v, expectResult = %v", result, true)
	}
}

func TestErrorToVerifyResult(t *testing.T) {
	policyEnforcer := &policyEnforcer{
		Policy:    "",
		OpaEngine: policyEngine{},
	}
	result := policyEnforcer.ErrorToVerifyResult(context.Background(), "", nil)

	if !reflect.DeepEqual(result, types.VerifyResult{}) {
		t.Fatalf("result = %v, expectResult = %v", result, types.VerifyResult{})
	}
}

func TestOverallVerifyResult(t *testing.T) {
	testcases := []struct {
		name               string
		reports            []interface{}
		passthroughEnabled bool
		returnErr          bool
		expectResult       bool
	}{
		{
			name:               "passthrough enabled",
			reports:            []interface{}{types.VerifyResult{}},
			passthroughEnabled: true,
			expectResult:       false,
			returnErr:          false,
		},
		{
			name:         "opa engine returns error",
			reports:      []interface{}{types.VerifyResult{}},
			expectResult: false,
			returnErr:    true,
		},
		{
			name:         "opa engine returns result",
			reports:      []interface{}{types.VerifyResult{}},
			expectResult: true,
			returnErr:    false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			policyEnforcer := &policyEnforcer{
				Policy: "",
				OpaEngine: policyEngine{
					ReturnErr: tc.returnErr,
				},
				passthroughEnabled: tc.passthroughEnabled,
			}
			result := policyEnforcer.OverallVerifyResult(context.Background(), tc.reports)
			if result != tc.expectResult {
				t.Fatalf("result = %v, expectResult = %v", result, tc.expectResult)
			}
		})
	}
}

func TestGetPolicyType(t *testing.T) {
	enforcer := policyEnforcer{}
	if policyType := enforcer.GetPolicyType(context.Background()); policyType != "regopolicy" {
		t.Fatalf("expected policy type: regopolicy, got %v", policyType)
	}
}
