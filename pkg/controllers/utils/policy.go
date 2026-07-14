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
	"encoding/json"
	"fmt"

	"github.com/notaryproject/ratify/v2/pkg/policyprovider"
	"github.com/notaryproject/ratify/v2/pkg/policyprovider/config"
	pf "github.com/notaryproject/ratify/v2/pkg/policyprovider/factory"
)

func SpecToPolicyEnforcer(raw []byte, policyType string) (policyprovider.PolicyProvider, error) {
	policyConfig, err := rawToPolicyConfig(raw, policyType)
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy config: %w", err)
	}

	policyEnforcer, err := pf.CreatePolicyProviderFromConfig(policyConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy provider: %w", err)
	}

	return policyEnforcer, nil
}

func rawToPolicyConfig(raw []byte, policyType string) (config.PoliciesConfig, error) {
	pluginConfig := config.PolicyPluginConfig{}

	if string(raw) == "" {
		return config.PoliciesConfig{}, fmt.Errorf("no policy parameters provided")
	}
	if err := json.Unmarshal(raw, &pluginConfig); err != nil {
		return config.PoliciesConfig{}, fmt.Errorf("unable to decode policy parameters.Raw: %s, err: %w", raw, err)
	}

	pluginConfig["name"] = policyType

	return config.PoliciesConfig{
		PolicyPlugin: pluginConfig,
	}, nil
}
