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

package utils

import (
	"reflect"
	"testing"

	configv1beta1 "github.com/notaryproject/ratify/v2/api/v1beta1"
	_ "github.com/notaryproject/ratify/v2/pkg/policyprovider/configpolicy"

	"github.com/notaryproject/ratify/v2/pkg/policyprovider/config"
	"k8s.io/apimachinery/pkg/runtime"
)

const policyName1 = "policy1"

func TestRawToPolicyConfig(t *testing.T) {
	testCases := []struct {
		name         string
		raw          []byte
		expectErr    bool
		expectConfig config.PoliciesConfig
	}{
		{
			name:         "empty Raw",
			raw:          []byte{},
			expectErr:    true,
			expectConfig: config.PoliciesConfig{},
		},
		{
			name:         "unmarshal failure",
			raw:          []byte("invalid"),
			expectErr:    true,
			expectConfig: config.PoliciesConfig{},
		},
		{
			name:      "valid Raw",
			raw:       []byte("{\"name\": \"policy1\"}"),
			expectErr: false,
			expectConfig: config.PoliciesConfig{
				PolicyPlugin: config.PolicyPluginConfig{
					"name": policyName1,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config, err := rawToPolicyConfig(tc.raw, policyName1)

			if tc.expectErr != (err != nil) {
				t.Fatalf("Expected error to be %t, got %t", tc.expectErr, err != nil)
			}
			if !reflect.DeepEqual(config, tc.expectConfig) {
				t.Fatalf("Expected config to be %v, got %v", tc.expectConfig, config)
			}
		})
	}
}

func TestSpecToPolicyEnforcer(t *testing.T) {
	testCases := []struct {
		name           string
		policyName     string
		spec           configv1beta1.PolicySpec
		expectErr      bool
		expectProvider bool
	}{
		{
			name:       "invalid spec",
			policyName: policyName1,
			spec: configv1beta1.PolicySpec{
				Type: policyName1,
			},
			expectErr:      true,
			expectProvider: false,
		},
		{
			name: "non-supported policy",
			spec: configv1beta1.PolicySpec{
				Parameters: runtime.RawExtension{
					Raw: []byte("{\"name\": \"policy1\"}"),
				},
				Type: policyName1,
			},
			expectErr:      true,
			expectProvider: false,
		},
		{
			name: "valid spec",
			spec: configv1beta1.PolicySpec{
				Parameters: runtime.RawExtension{
					Raw: []byte("{\"name\": \"configpolicy\"}"),
				},
				Type: "configpolicy",
			},
			expectErr:      false,
			expectProvider: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := SpecToPolicyEnforcer(tc.spec.Parameters.Raw, tc.spec.Type)

			if tc.expectErr != (err != nil) {
				t.Fatalf("Expected error to be %t, got %t", tc.expectErr, err != nil)
			}
			if tc.expectProvider != (provider != nil) {
				t.Fatalf("expected provider to be %t, got %t", tc.expectProvider, provider != nil)
			}
		})
	}
}
