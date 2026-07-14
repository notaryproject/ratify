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
	"encoding/json"
	"fmt"

	re "github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/executor/types"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/policyprovider"
	"github.com/notaryproject/ratify/v2/pkg/policyprovider/config"
	pf "github.com/notaryproject/ratify/v2/pkg/policyprovider/factory"
	vt "github.com/notaryproject/ratify/v2/pkg/policyprovider/types"
	"github.com/notaryproject/ratify/v2/pkg/verifier"
)

// PolicyEnforcer describes different polices that are enforced during verification
type PolicyEnforcer struct {
	ArtifactTypePolicies map[string]vt.ArtifactTypeVerifyPolicy
}

type configPolicyEnforcerConf struct {
	Name                         string                                 `json:"name"`
	ArtifactVerificationPolicies map[string]vt.ArtifactTypeVerifyPolicy `json:"artifactVerificationPolicies,omitempty"`
}

const (
	defaultPolicyName = "default"
)

type configPolicyFactory struct{}

// init calls Register for our config policy provider
func init() {
	pf.Register(vt.ConfigPolicy, &configPolicyFactory{})
}

// Create initializes a new policy provider based on the provider selected in config
func (f *configPolicyFactory) Create(policyConfig config.PolicyPluginConfig) (policyprovider.PolicyProvider, error) {
	policyEnforcer := PolicyEnforcer{}

	conf := configPolicyEnforcerConf{}
	policyProviderConfigBytes, err := json.Marshal(policyConfig)
	if err != nil {
		return nil, re.ErrorCodeDataEncodingFailure.NewError(re.PolicyProvider, vt.ConfigPolicy, re.PolicyProviderLink, err, "failed to marshal policy config", re.HideStackTrace)
	}

	if err := json.Unmarshal(policyProviderConfigBytes, &conf); err != nil {
		return nil, re.ErrorCodeDataDecodingFailure.NewError(re.PolicyProvider, vt.ConfigPolicy, re.PolicyProviderLink, err, "failed to unmarshal policy config", re.HideStackTrace)
	}

	if conf.ArtifactVerificationPolicies == nil {
		policyEnforcer.ArtifactTypePolicies = map[string]vt.ArtifactTypeVerifyPolicy{}
	} else {
		policyEnforcer.ArtifactTypePolicies = conf.ArtifactVerificationPolicies
	}
	if policyEnforcer.ArtifactTypePolicies[defaultPolicyName] == "" {
		policyEnforcer.ArtifactTypePolicies[defaultPolicyName] = vt.AllVerifySuccess
	}
	return &policyEnforcer, nil
}

// VerifyNeeded determines if the given subject/reference artifact should be verified
func (enforcer PolicyEnforcer) VerifyNeeded(_ context.Context, _ common.Reference, _ ocispecs.ReferenceDescriptor) bool {
	return true
}

// ContinueVerifyOnFailure determines if the given error can be ignored and verification can be continued.
func (enforcer PolicyEnforcer) ContinueVerifyOnFailure(_ context.Context, _ common.Reference, referenceDesc ocispecs.ReferenceDescriptor, _ types.VerifyResult) bool {
	artifactType := referenceDesc.ArtifactType
	policy := enforcer.ArtifactTypePolicies[artifactType]
	if policy == "" {
		policy = enforcer.ArtifactTypePolicies[defaultPolicyName]
	}
	if policy == vt.AnyVerifySuccess {
		return true
	}
	return false
}

// ErrorToVerifyResult converts an error to a properly formatted verify result
func (enforcer PolicyEnforcer) ErrorToVerifyResult(_ context.Context, subjectRefString string, verifyError error) types.VerifyResult {
	verifierErr := re.ErrorCodeVerifyReferenceFailure.WithDetail(fmt.Sprintf("failed to verify artifact: %s", subjectRefString)).WithError(verifyError)
	errorReport := verifier.NewVerifierResult(subjectRefString, "", "", "", false, &verifierErr, nil)
	reports := make([]interface{}, 0, 1)
	reports = append(reports, errorReport)
	return types.VerifyResult{IsSuccess: false, VerifierReports: reports}
}

// OverallVerifyResult determines the final outcome of verification that is constructed using the results from
// individual verifications
func (enforcer PolicyEnforcer) OverallVerifyResult(_ context.Context, verifierReports []interface{}) bool {
	if len(verifierReports) <= 0 {
		return false
	}

	// use boolean map to track if each artifact type policy constraint is satisfied
	verifySuccess := map[string]bool{}
	for artifactType := range enforcer.ArtifactTypePolicies {
		// add all policies except for default
		if artifactType != defaultPolicyName {
			verifySuccess[artifactType] = false
		}
	}

	for _, report := range verifierReports {
		castedReport := report.(verifier.VerifierResult)
		// extract the policy for the artifact type of the verified artifact if specified
		policyType, ok := enforcer.ArtifactTypePolicies[castedReport.ArtifactType]
		// if artifact type policy not specified, set policy to be default policy and add artifact type to success map
		if !ok {
			policyType = enforcer.ArtifactTypePolicies[defaultPolicyName]
		}
		// set the artifact type success field in map to false to start
		if _, ok = verifySuccess[castedReport.ArtifactType]; !ok {
			verifySuccess[castedReport.ArtifactType] = false
		}

		if policyType == vt.AnyVerifySuccess && castedReport.IsSuccess {
			// if policy is 'any' and report is successful
			verifySuccess[castedReport.ArtifactType] = true
		} else if policyType == vt.AllVerifySuccess {
			// if policy is 'all'
			if !castedReport.IsSuccess {
				// return false after first failure
				return false
			}
			verifySuccess[castedReport.ArtifactType] = true
		}
	}

	// all booleans in map must be true for overall success to be true
	for artifactType := range verifySuccess {
		if !verifySuccess[artifactType] {
			return false
		}
	}
	return true
}

// GetPolicyType returns the type of the policy.
func (enforcer PolicyEnforcer) GetPolicyType(_ context.Context) string {
	return vt.ConfigPolicy
}
