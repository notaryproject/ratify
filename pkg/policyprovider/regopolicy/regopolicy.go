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
	"encoding/json"
	"fmt"
	"os"

	re "github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/internal/logger"
	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/executor/types"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/policyprovider"
	"github.com/notaryproject/ratify/v2/pkg/policyprovider/config"
	pf "github.com/notaryproject/ratify/v2/pkg/policyprovider/factory"
	"github.com/notaryproject/ratify/v2/pkg/policyprovider/policyengine"
	opa "github.com/notaryproject/ratify/v2/pkg/policyprovider/policyengine/opaengine"
	query "github.com/notaryproject/ratify/v2/pkg/policyprovider/policyquery/rego"
	policyTypes "github.com/notaryproject/ratify/v2/pkg/policyprovider/types"
)

type policyEnforcer struct {
	Policy             string
	OpaEngine          policyengine.PolicyEngine
	passthroughEnabled bool
}

type policyEnforcerConf struct {
	Name               string `json:"name"`
	Policy             string `json:"policy"`
	PolicyPath         string `json:"policyPath"`
	PassthroughEnabled bool   `json:"passthroughEnabled"`
}

// Factory is a factory for creating rego policy enforcers.
type Factory struct{}

var logOpt = logger.Option{
	ComponentType: logger.PolicyProvider,
}

// init calls Register for our rego policy provider.
func init() {
	pf.Register(policyTypes.RegoPolicy, &Factory{})
}

// Create creates a new policy enforcer based on the policy provided in config.
func (f *Factory) Create(policyConfig config.PolicyPluginConfig) (policyprovider.PolicyProvider, error) {
	conf := policyEnforcerConf{}
	policyProviderConfigBytes, err := json.Marshal(policyConfig)
	if err != nil {
		return nil, re.ErrorCodeConfigInvalid.NewError(re.PolicyProvider, policyTypes.RegoPolicy, re.PolicyProviderLink, err, "failed to marshal policy config", re.HideStackTrace)
	}

	if err := json.Unmarshal(policyProviderConfigBytes, &conf); err != nil {
		return nil, re.ErrorCodeConfigInvalid.NewError(re.PolicyProvider, policyTypes.RegoPolicy, re.EmptyLink, err, "failed to parse policy provider configuration", re.HideStackTrace)
	}
	if conf.Policy == "" {
		body, err := os.ReadFile(conf.PolicyPath)
		if err != nil {
			return nil, re.ErrorCodeConfigInvalid.NewError(re.PolicyProvider, policyTypes.RegoPolicy, re.PolicyProviderLink, err, fmt.Sprintf("unable to read rego policy file at path: %s", conf.PolicyPath), false)
		}
		conf.Policy = string(body)
	}
	if conf.Policy == "" {
		return nil, re.ErrorCodeConfigInvalid.NewError(re.PolicyProvider, policyTypes.RegoPolicy, re.PolicyProviderLink, nil, "policy is required for rego policy provider", re.HideStackTrace)
	}

	engine, err := policyengine.CreateEngineFromConfig(policyengine.Config{
		Name:          opa.OPA,
		QueryLanguage: query.RegoName,
		Policy:        conf.Policy,
	})
	if err != nil {
		return nil, re.ErrorCodePluginInitFailure.NewError(re.PolicyProvider, policyTypes.RegoPolicy, re.PolicyProviderLink, err, "failed to create OPA engine", re.HideStackTrace)
	}

	policyEnforcer := &policyEnforcer{
		Policy:             conf.Policy,
		OpaEngine:          engine,
		passthroughEnabled: conf.PassthroughEnabled,
	}

	return policyEnforcer, nil
}

// VerifyNeeded determines if verification should be performed for a given artifact.
func (e *policyEnforcer) VerifyNeeded(_ context.Context, _ common.Reference, _ ocispecs.ReferenceDescriptor) bool {
	return true
}

// ContinueVerifyOnFailure determines if verification should continue if a previous verification failed.
func (e *policyEnforcer) ContinueVerifyOnFailure(_ context.Context, _ common.Reference, _ ocispecs.ReferenceDescriptor, _ types.VerifyResult) bool {
	return true
}

// ErrorToVerifyResult converts an error to a VerifyResult.
func (e *policyEnforcer) ErrorToVerifyResult(_ context.Context, _ string, _ error) types.VerifyResult {
	return types.VerifyResult{}
}

// OverallVerifyResult determines if the overall verification result should be a success or failure.
func (e *policyEnforcer) OverallVerifyResult(ctx context.Context, verifierReports []interface{}) bool {
	if e.passthroughEnabled {
		return false
	}

	nestedReports := map[string]interface{}{}
	nestedReports["verifierReports"] = verifierReports
	result, err := e.OpaEngine.Evaluate(ctx, nestedReports)
	if err != nil {
		logger.GetLogger(ctx, logOpt).Errorf("failed to evaluate policy: %v", err)
		return false
	}
	return result
}

// GetPolicyType returns the type of the policy.
func (e *policyEnforcer) GetPolicyType(_ context.Context) string {
	return policyTypes.RegoPolicy
}
