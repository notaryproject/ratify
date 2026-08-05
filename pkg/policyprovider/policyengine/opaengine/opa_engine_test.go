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

package opa

import (
	"context"
	"testing"

	query "github.com/notaryproject/ratify/v2/pkg/policyprovider/policyquery/rego"
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

type mockQuery struct{}

func (q *mockQuery) Evaluate(_ context.Context, _ map[string]interface{}) (bool, error) {
	return true, nil
}

func TestCreate(t *testing.T) {
	testcases := []struct {
		name          string
		policy        string
		queryLanguage string
		expectErr     bool
		expectEngine  bool
	}{
		{
			name:          "empty policy",
			policy:        "",
			queryLanguage: "",
			expectErr:     true,
			expectEngine:  false,
		},
		{
			name:          "invalid policy",
			policy:        policy2,
			queryLanguage: query.RegoName,
			expectErr:     true,
			expectEngine:  false,
		},
		{
			name:          "valid policy",
			policy:        policy1,
			queryLanguage: query.RegoName,
			expectErr:     false,
			expectEngine:  true,
		},
	}

	for _, tc := range testcases {
		factory := &EngineFactory{}
		engine, err := factory.Create(tc.policy, tc.queryLanguage)
		if tc.expectErr != (err != nil) {
			t.Fatalf("error = %v, expectErr = %v", err, tc.expectErr)
		}
		if tc.expectEngine != (engine != nil) {
			t.Fatalf("engine = %v, expectEngine = %v", engine, tc.expectEngine)
		}
	}
}

func TestEvaluate(t *testing.T) {
	engine := &Engine{
		query: &mockQuery{},
	}
	result, err := engine.Evaluate(context.Background(), nil)
	if err != nil {
		t.Fatalf("expect no err, but got err: %v", err)
	}
	if !result {
		t.Fatalf("expect result to be true")
	}
}
