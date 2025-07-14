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
	"reflect"
	"testing"

	"github.com/notaryproject/ratify-go"
)

func TestRegister(t *testing.T) {
	testCreate := func(_ NewOptions) (ratify.PolicyEnforcer, error) {
		return nil, nil
	}

	tests := []struct {
		name       string
		policyType string
		create     func(NewOptions) (ratify.PolicyEnforcer, error)
		wantPanic  string
	}{
		{
			name:      "empty policy type",
			create:    testCreate,
			wantPanic: "policy type cannot be empty",
		},
		{
			name:       "nil create function",
			policyType: "test",
			wantPanic:  "policy create cannot be nil",
		},
		{
			name:       "valid registration",
			policyType: "valid-type",
			create:     testCreate,
		},
		{
			name:       "duplicate registration",
			policyType: "valid-type",
			create:     testCreate,
			wantPanic:  "policy factory already registered",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantPanic != "" {
				defer func() {
					if r := recover(); r != tt.wantPanic {
						t.Errorf("Register() panic = %v, wantPanic %v", r, tt.wantPanic)
					}
				}()
			}
			Register(tt.policyType, tt.create)
		})
	}
}

type mockPolicyEnforcer struct{}

func (m *mockPolicyEnforcer) Evaluator(_ context.Context, _ string) (ratify.Evaluator, error) {
	return nil, nil
}

func createMockPolicyEnforcer(_ NewOptions) (ratify.PolicyEnforcer, error) {
	return &mockPolicyEnforcer{}, nil
}

func TestNew(t *testing.T) {
	testPolicyEnforcer := &mockPolicyEnforcer{}
	testOptions := NewOptions{
		Type: "testNew-type",
	}
	Register(testOptions.Type, createMockPolicyEnforcer)
	defer delete(registry, testOptions.Type) // Clean up after test

	tests := []struct {
		name    string
		opts    NewOptions
		want    ratify.PolicyEnforcer
		wantErr string
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
			wantErr: "policy factory of type unregistered is not registered",
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
			if (err == nil && tt.wantErr != "") || (err != nil && err.Error() != tt.wantErr) {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}
