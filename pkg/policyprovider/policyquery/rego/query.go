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

package query

import (
	"context"
	"fmt"

	//nolint:staticcheck // SA1019 OPA rego package is deprecated but still in use for compatibility
	"github.com/notaryproject/ratify/v2/pkg/policyprovider/policyquery"
	"github.com/open-policy-agent/opa/rego"
	"github.com/pkg/errors"
)

const (
	query = "data.ratify.policy.valid"
	// RegoName is a constant for "rego"
	RegoName = "rego"
)

// Rego is a wrapper around the OPA rego library.
type Rego struct {
	query rego.PreparedEvalQuery
}

// RegoFactory is a factory for creating Rego query objects.
type RegoFactory struct{}

func init() {
	policyquery.Register(RegoName, &RegoFactory{})
}

// Create creates a new Rego query object.
func (f *RegoFactory) Create(policy string) (policyquery.PolicyQuery, error) {
	query, err := rego.New(
		rego.Query(query),
		rego.Module("policy.rego", policy),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to prepare rego query, err: %+w", err)
	}

	return &Rego{query: query}, nil
}

// Evaluate evaluates the policy against the input.
func (r *Rego) Evaluate(ctx context.Context, input map[string]interface{}) (bool, error) {
	results, err := r.query.Eval(ctx, rego.EvalInput(input))

	if err != nil {
		return false, err
	} else if len(results) == 0 || len(results[0].Expressions) == 0 {
		return false, errors.New("no results returned from query")
	}

	result, ok := results[0].Expressions[0].Value.(bool)
	if !ok {
		return false, fmt.Errorf("unexpected result type: %v", results[0].Expressions[0].Value)
	}
	return result, nil
}
