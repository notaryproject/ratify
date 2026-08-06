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

package azure

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// CreateCredentialChain creates a ChainedTokenCredential with the specified
// order: workload identity, managed identity.
// Note: credentials are cached in memory by default.
func CreateCredentialChain(clientID, tenantID string) (azcore.TokenCredential, error) {
	return CreateCredentialChainWithIdentityBinding(clientID, tenantID, nil)
}

// CreateCredentialChainWithIdentityBinding builds the Azure token credential
// used to authenticate to ACR.
func CreateCredentialChainWithIdentityBinding(clientID, tenantID string, ibConfig *IdentityBindingConfig) (azcore.TokenCredential, error) {
	// Identity binding, when configured, is the sole credential source.
	if ibConfig != nil && ibConfig.SNIName != "" {
		ibCred, err := newIdentityBindingCredential(clientID, *ibConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create identity binding credential: %w", err)
		}
		return ibCred, nil
	}

	var sources []azcore.TokenCredential

	// 1. Try Workload Identity first
	wiCred, err := azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{
		// Optionally set the client ID and tenant ID if needed
		ClientID: clientID,
		TenantID: tenantID,
	})
	if err == nil {
		sources = append(sources, wiCred)
	}

	// 2. Try Managed Identity second
	miOpts := &azidentity.ManagedIdentityCredentialOptions{}
	if clientID != "" {
		// If a user-managed identity is specified, set the client ID.
		// This is optional; if not set, it will use the system-assigned identity.
		miOpts.ID = azidentity.ClientID(clientID)
	}
	miCred, err := azidentity.NewManagedIdentityCredential(miOpts)
	if err == nil {
		sources = append(sources, miCred)
	}

	// Fail clearly when no credential source could be constructed rather than
	// deferring to a less obvious error from the chained credential.
	if len(sources) == 0 {
		return nil, fmt.Errorf("no Azure credential sources available: neither workload identity nor managed identity could be configured")
	}

	// 3. Create chained credential
	return azidentity.NewChainedTokenCredential(sources, nil)
}
