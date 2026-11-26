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

package policyenforcer

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify-go/plugin"
)

type mockPolicyEnforcer struct{}

func (m *mockPolicyEnforcer) Evaluator(_ context.Context, _ string) (ratify.Evaluator, error) {
	return nil, nil
}

// gotParams records the parameters passed to createMockPolicyEnforcer.
var gotParams json.RawMessage

func createMockPolicyEnforcer(_ context.Context, opts plugin.PolicyEnforcerOptions) (ratify.PolicyEnforcer, error) {
	gotParams = opts.Parameters
	return &mockPolicyEnforcer{}, nil
}

var errMockFactory = errors.New("mock factory error")

func createFailingPolicyEnforcer(_ context.Context, _ plugin.PolicyEnforcerOptions) (ratify.PolicyEnforcer, error) {
	return nil, errMockFactory
}

func TestNew(t *testing.T) {
	testPolicyEnforcer := &mockPolicyEnforcer{}
	testOptions := NewOptions{
		Type:       "testNew-type",
		Parameters: map[string]any{"key": "value"},
	}
	// The errors are ignored so that the test can be run multiple times in the
	// same process (e.g. go test -count=2).
	_ = plugin.Default.RegisterPolicyEnforcer(testOptions.Type, createMockPolicyEnforcer)
	_ = plugin.Default.RegisterPolicyEnforcer("testNew-failing-type", createFailingPolicyEnforcer)

	tests := []struct {
		name      string
		opts      NewOptions
		want      ratify.PolicyEnforcer
		wantErr   string
		wantErrIs error
	}{
		{
			name:    "empty type",
			wantErr: "policy type is not provided in the policy options",
		},
		{
			name: "unregistered type",
			opts: NewOptions{
				Type: "unregistered",
			},
			wantErr:   `policy enforcer type "unregistered"`,
			wantErrIs: plugin.ErrNotRegistered,
		},
		{
			name: "unmarshalable parameters",
			opts: NewOptions{
				Type:       testOptions.Type,
				Parameters: make(chan int),
			},
			wantErr: "failed to marshal policy enforcer parameters",
		},
		{
			name: "factory error",
			opts: NewOptions{
				Type: "testNew-failing-type",
			},
			wantErr:   `failed to create policy enforcer of type "testNew-failing-type"`,
			wantErrIs: errMockFactory,
		},
		{
			name: "registered type",
			opts: testOptions,
			want: testPolicyEnforcer,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.opts)
			if (err == nil) != (tt.wantErr == "") || (err != nil && !strings.Contains(err.Error(), tt.wantErr)) {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
				t.Errorf("New() error = %v, want errors.Is %v", err, tt.wantErrIs)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}

	if string(gotParams) != `{"key":"value"}` {
		t.Errorf("parameters passed to the factory = %s, want %s", gotParams, `{"key":"value"}`)
	}
}
