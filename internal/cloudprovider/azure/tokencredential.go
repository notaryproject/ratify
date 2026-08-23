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
	"github.com/sirupsen/logrus"
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
			logrus.Debugf("azure: identity binding credential is unavailable (clientID=%q, sniName=%q): %v", clientID, ibConfig.SNIName, err)
			return nil, fmt.Errorf("failed to create identity binding credential: %w", err)
		}
		logrus.Debugf("azure: using the identity binding credential exclusively (clientID=%q, sniName=%q)", clientID, ibConfig.SNIName)
		return ibCred, nil
	}

	var sources []azcore.TokenCredential

	// 1. Try Workload Identity first
	wiCred, err := azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{
		// Optionally set the client ID and tenant ID if needed
		ClientID: clientID,
		TenantID: tenantID,
	})
	sources = appendCredential(sources, wiCred, err, "workload identity", fmt.Sprintf("clientID=%q, tenantID=%q", clientID, tenantID))

	// 2. Try Managed Identity second
	miOpts := &azidentity.ManagedIdentityCredentialOptions{}
	if clientID != "" {
		// If a user-managed identity is specified, set the client ID.
		// This is optional; if not set, it will use the system-assigned identity.
		miOpts.ID = azidentity.ClientID(clientID)
	}
	miCred, err := azidentity.NewManagedIdentityCredential(miOpts)
	sources = appendCredential(sources, miCred, err, "managed identity", fmt.Sprintf("clientID=%q", clientID))

	logrus.Debugf("azure: built credential chain with %d source(s)", len(sources))

	// Fail clearly when no credential source could be constructed rather than
	// deferring to a less obvious error from the chained credential.
	if len(sources) == 0 {
		return nil, fmt.Errorf("no Azure credential sources available: neither workload identity nor managed identity could be configured")
	}

	// 3. Create chained credential
	return azidentity.NewChainedTokenCredential(sources, nil)
}

// appendCredential adds cred to sources when it was created successfully. Both
// outcomes are logged so that operators can tell which identity sources the
// pod actually has available.
func appendCredential(sources []azcore.TokenCredential, cred azcore.TokenCredential, err error, name, details string) []azcore.TokenCredential {
	if err != nil {
		logrus.Debugf("azure: %s credential is unavailable (%s): %v", name, details, err)
		return sources
	}
	logrus.Debugf("azure: %s credential is available (%s)", name, details)
	return append(sources, cred)
}
