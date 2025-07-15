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

package threshold

import (
	"reflect"
	"testing"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify/v2/internal/policyenforcer"
)

func TestNewThresholdPolicyEnforcer(t *testing.T) {
	tests := []struct {
		name       string
		parameters any
		wantErr    bool
	}{
		{
			name:       "unsupported params",
			parameters: make(chan int),
			wantErr:    true,
		},
		{
			name:       "malformed params",
			parameters: "{",
			wantErr:    true,
		},
		{
			name:       "nil policy",
			parameters: map[string]any{},
			wantErr:    true,
		},
		{
			name: "no rules provided",
			parameters: map[string]any{
				"policy": map[string]any{},
			},
			wantErr: true,
		},
		{
			name: "embedded nil rules",
			parameters: map[string]any{
				"policy": map[string]any{
					"rules": nil,
				},
			},
			wantErr: true,
		},
		{
			name: "Valid rules",
			parameters: map[string]any{
				"policy": map[string]any{
					"rules": []map[string]any{
						{
							"verifierName": "test-verifier",
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := policyenforcer.NewOptions{
				Type:       "threshold-policy",
				Parameters: tt.parameters,
			}
			_, err := policyenforcer.New(opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_parseRule(t *testing.T) {
	tests := []struct {
		name    string
		raw     map[string]any
		want    *ratify.ThresholdPolicyRule
		wantErr bool
	}{
		{
			name:    "nil raw",
			raw:     nil,
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid verifier type",
			raw:     map[string]any{"verifierName": 123},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid threshold type",
			raw:     map[string]any{"threshold": "bad"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid rules type",
			raw:     map[string]any{"rules": "not slice"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "nested rule error",
			raw:     map[string]any{"rules": []map[string]any{{"verifierName": 999}}},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid minimal", // only valid for parseRule, not ratify.NewThresholdPolicyEnforcer
			raw:  map[string]any{},
			want: &ratify.ThresholdPolicyRule{},
		},
		{
			name: "valid full",
			raw: map[string]any{
				"verifierName": "root",
				"threshold":    2,
				"rules": []map[string]any{
					{
						"verifierName": "child",
						"threshold":    1,
					},
				},
			},
			want: &ratify.ThresholdPolicyRule{
				Verifier:  "root",
				Threshold: 2,
				Rules: []*ratify.ThresholdPolicyRule{
					{
						Verifier:  "child",
						Threshold: 1,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRule(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseRule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseRule() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseOrNil(t *testing.T) {
	data := map[string]any{
		"int":    42,
		"string": "test",
		"bool":   true,
		"nil":    nil,
		"slice":  []any{1, 2, 3},
		"map": map[string]any{
			"key": "value",
		},
	}
	tests := []struct {
		name    string
		key     string
		want    map[string]any
		wantErr bool
	}{
		{
			name:    "existing int",
			key:     "int",
			wantErr: true,
		},
		{
			name:    "existing string",
			key:     "string",
			wantErr: true,
		},
		{
			name:    "existing bool",
			key:     "bool",
			wantErr: true,
		},
		{
			name: "existing nil",
			key:  "nil",
			want: nil,
		},
		{
			name:    "existing slice",
			key:     "slice",
			wantErr: true,
		},
		{
			name: "existing map",
			key:  "map",
			want: map[string]any{"key": "value"},
		},
		{
			name: "missing key",
			key:  "notfound",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseOrNil[map[string]any](data, tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseOrNil() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseOrNil() = %v, want %v", got, tt.want)
			}
		})
	}
}
