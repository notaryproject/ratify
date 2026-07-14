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

package configpolicy

import (
	"context"
	"testing"

	"github.com/notaryproject/ratify/v2/pkg/common"
	vt "github.com/notaryproject/ratify/v2/pkg/executor/types"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	pc "github.com/notaryproject/ratify/v2/pkg/policyprovider/config"
	pf "github.com/notaryproject/ratify/v2/pkg/policyprovider/factory"
	"github.com/notaryproject/ratify/v2/pkg/policyprovider/types"
	vr "github.com/notaryproject/ratify/v2/pkg/verifier"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestPolicyEnforcer_ContinueVerifyOnFailure(t *testing.T) {
	configPolicyConfig := map[string]interface{}{
		"name": "configPolicy",
		"artifactVerificationPolicies": map[string]types.ArtifactTypeVerifyPolicy{
			"application/vnd.cncf.notary.signature": "any",
			"application/spdx+json":                 "all",
			"default":                               "any",
		},
	}
	config := pc.PoliciesConfig{
		Version:      "1.0.0",
		PolicyPlugin: configPolicyConfig,
	}

	policyEnforcer, err := pf.CreatePolicyProviderFromConfig(config)

	if err != nil {
		t.Fatalf("PolicyEnforcer should create from PoliciesConfig")
	}

	ctx := context.Background()
	subjectReference := common.Reference{
		Path:     "",
		Digest:   "",
		Tag:      "",
		Original: "",
	}
	referenceDesc := ocispecs.ReferenceDescriptor{
		Descriptor:   oci.Descriptor{},
		ArtifactType: "application/vnd.cncf.notary.signature",
	}
	result := vt.VerifyResult{
		IsSuccess:       false,
		VerifierReports: nil,
	}

	check := policyEnforcer.ContinueVerifyOnFailure(ctx, subjectReference, referenceDesc, result)

	if check != true {
		t.Fatalf("For policy of 'any' PolicyEnforcer should allow continuing on verify failure")
	}

	referenceDesc.ArtifactType = "application/spdx+json"

	check = policyEnforcer.ContinueVerifyOnFailure(ctx, subjectReference, referenceDesc, result)

	if check != false {
		t.Fatalf("For policy 'all' PolicyEnforcer should not allow continuing on verify failure")
	}

	referenceDesc.ArtifactType = "unknown"

	check = policyEnforcer.ContinueVerifyOnFailure(ctx, subjectReference, referenceDesc, result)

	if check != true {
		t.Fatalf("For artifact types without a policy the default policy should be followed")
	}
}

func TestPolicyEnforcer_OverallVerifyResult(t *testing.T) {
	testcases := []struct {
		configPolicyConfig map[string]interface{}
		verifierReports    []interface{}
		output             bool
	}{
		{
			// no artifact policies or verifier reports
			configPolicyConfig: map[string]interface{}{
				"name":                         "configPolicy",
				"artifactVerificationPolicies": map[string]types.ArtifactTypeVerifyPolicy{},
			},
			verifierReports: []interface{}{},
			output:          false,
		},
		{
			// no artifact policies
			configPolicyConfig: map[string]interface{}{
				"name":                         "configPolicy",
				"artifactVerificationPolicies": map[string]types.ArtifactTypeVerifyPolicy{},
			},
			verifierReports: []interface{}{
				vr.VerifierResult{
					Subject:      "",
					IsSuccess:    false,
					ArtifactType: "application/vnd.cncf.notary.signature",
				},
			},
			output: false,
		},
		{
			// no artifact policies but 1 verifier result is false
			configPolicyConfig: map[string]interface{}{
				"name":                         "configPolicy",
				"artifactVerificationPolicies": map[string]types.ArtifactTypeVerifyPolicy{},
			},
			verifierReports: []interface{}{
				vr.VerifierResult{
					Subject:      "",
					IsSuccess:    true,
					ArtifactType: "application/vnd.cncf.notary.signature",
				},
				vr.VerifierResult{
					Subject:      "",
					IsSuccess:    false,
					ArtifactType: "application/vnd.cncf.notary.signature",
				},
			},
			output: false,
		},
		{
			// no artifact policies but default relaxed to 'any' and 1 verifier result is false
			configPolicyConfig: map[string]interface{}{
				"name": "configPolicy",
				"artifactVerificationPolicies": map[string]types.ArtifactTypeVerifyPolicy{
					"default": "any",
				},
			},
			verifierReports: []interface{}{
				vr.VerifierResult{
					Subject:      "",
					IsSuccess:    true,
					ArtifactType: "application/vnd.cncf.notary.signature",
				},
				vr.VerifierResult{
					Subject:      "",
					IsSuccess:    false,
					ArtifactType: "application/vnd.cncf.notary.signature",
				},
			},
			output: true,
		},
		{
			// any notation artifact policy but no artifact verifier reports
			configPolicyConfig: map[string]interface{}{
				"name": "configPolicy",
				"artifactVerificationPolicies": map[string]types.ArtifactTypeVerifyPolicy{
					"application/vnd.cncf.notary.signature": "any",
				},
			},
			verifierReports: []interface{}{},
			output:          false,
		},
		{
			// any notation artifact policy and only 1 notation report is true
			configPolicyConfig: map[string]interface{}{
				"name": "configPolicy",
				"artifactVerificationPolicies": map[string]types.ArtifactTypeVerifyPolicy{
					"application/vnd.cncf.notary.signature": "any",
				},
			},
			verifierReports: []interface{}{
				vr.VerifierResult{
					Subject:      "",
					IsSuccess:    true,
					ArtifactType: "application/vnd.cncf.notary.signature",
				},
				vr.VerifierResult{
					Subject:      "",
					IsSuccess:    false,
					ArtifactType: "application/vnd.cncf.notary.signature",
				},
			},
			output: true,
		},
		{
			// all notation artifact policy but only 1 notation report is true
			configPolicyConfig: map[string]interface{}{
				"name": "configPolicy",
				"artifactVerificationPolicies": map[string]types.ArtifactTypeVerifyPolicy{
					"application/vnd.cncf.notary.signature": "all",
				},
			},
			verifierReports: []interface{}{
				vr.VerifierResult{
					Subject:      "",
					IsSuccess:    true,
					ArtifactType: "application/vnd.cncf.notary.signature",
				},
				vr.VerifierResult{
					Subject:      "",
					IsSuccess:    false,
					ArtifactType: "application/vnd.cncf.notary.signature",
				},
			},
			output: false,
		},
		{
			// all notation artifact policy and both notation reports are true
			configPolicyConfig: map[string]interface{}{
				"name": "configPolicy",
				"artifactVerificationPolicies": map[string]types.ArtifactTypeVerifyPolicy{
					"application/vnd.cncf.notary.signature": "all",
				},
			},
			verifierReports: []interface{}{
				vr.VerifierResult{
					Subject:      "",
					IsSuccess:    true,
					ArtifactType: "application/vnd.cncf.notary.signature",
				},
				vr.VerifierResult{
					Subject:      "",
					IsSuccess:    true,
					ArtifactType: "application/vnd.cncf.notary.signature",
				},
			},
			output: true,
		},
		{
			// any notation artifact policy, any sbom artifact policy and notation report is true and sbom is false
			configPolicyConfig: map[string]interface{}{
				"name": "configPolicy",
				"artifactVerificationPolicies": map[string]types.ArtifactTypeVerifyPolicy{
					"application/vnd.cncf.notary.signature": "any",
					"application/spdx+json":                 "any",
				},
			},
			verifierReports: []interface{}{
				vr.VerifierResult{
					Subject:      "",
					IsSuccess:    true,
					ArtifactType: "application/vnd.cncf.notary.signature",
				},
				vr.VerifierResult{
					Subject:      "",
					IsSuccess:    false,
					ArtifactType: "application/spdx+json",
				},
			},
			output: false,
		},
		{
			// any notation artifact policy, all sbom artifact policy, and both notation and sbom are true
			configPolicyConfig: map[string]interface{}{
				"name": "configPolicy",
				"artifactVerificationPolicies": map[string]types.ArtifactTypeVerifyPolicy{
					"application/vnd.cncf.notary.signature": "any",
					"application/spdx+json":                 "all",
				},
			},
			verifierReports: []interface{}{
				vr.VerifierResult{
					Subject:      "",
					IsSuccess:    true,
					ArtifactType: "application/vnd.cncf.notary.signature",
				},
				vr.VerifierResult{
					Subject:      "",
					IsSuccess:    true,
					ArtifactType: "application/spdx+json",
				},
			},
			output: true,
		},
	}

	ctx := context.Background()

	for _, testcase := range testcases {
		config := pc.PoliciesConfig{
			Version:      "1.0.0",
			PolicyPlugin: testcase.configPolicyConfig,
		}

		policyEnforcer, err := pf.CreatePolicyProviderFromConfig(config)
		if err != nil {
			t.Fatalf("PolicyEnforcer should create from PoliciesConfig")
		}

		overallVerifyResult := policyEnforcer.OverallVerifyResult(ctx, testcase.verifierReports)
		if overallVerifyResult != testcase.output {
			t.Fatalf("Expected %v from OverallVerifyResult but got %v", testcase.output, overallVerifyResult)
		}
	}
}

func TestGetPolicyType(t *testing.T) {
	enforcer := PolicyEnforcer{}
	if policyType := enforcer.GetPolicyType(context.Background()); policyType != "configpolicy" {
		t.Fatalf("expected policy type: configpolicy, got %v", policyType)
	}
}
