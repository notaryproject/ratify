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

package azureauth

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/ratify-project/ratify/pkg/metrics"
)

// Source: https://github.com/Azure/azure-workload-identity/blob/d126293e3c7c669378b225ad1b1f29cf6af4e56d/examples/msal-go/token_credential.go#L25
func GetAADAccessToken(ctx context.Context, tenantID, clientID, scope string) (confidential.AuthResult, error) {
	startTime := time.Now()
	defer func() {
		metrics.ReportAADExchangeDuration(ctx, time.Since(startTime).Milliseconds(), scope)
	}()
	// Azure AD Workload Identity webhook will inject the following env vars:
	// 	AZURE_FEDERATED_TOKEN_FILE is the service account token path
	// 	AZURE_AUTHORITY_HOST is the AAD authority hostname

	tokenFilePath := os.Getenv("AZURE_FEDERATED_TOKEN_FILE")
	authority := os.Getenv("AZURE_AUTHORITY_HOST")

	if tokenFilePath == "" || authority == "" {
		return confidential.AuthResult{}, fmt.Errorf("required environment variables not set, AZURE_FEDERATED_TOKEN_FILE: %s, AZURE_AUTHORITY_HOST: %s", tokenFilePath, authority)
	}

	cred := confidential.NewCredFromAssertionCallback(func(context.Context, confidential.AssertionRequestOptions) (string, error) {
		// read the service account token from the filesystem
		return readJWTFromFS(tokenFilePath)
	})

	// join the authority prefix with tenantID to create authority URL
	authorityURL, err := url.JoinPath(authority, tenantID)
	if err != nil {
		return confidential.AuthResult{}, fmt.Errorf("failed to create authority URL when joining authority prefix and tenantID: %w", err)
	}

	// create the confidential client to request an AAD token
	confidentialClientApp, err := confidential.New(
		authorityURL,
		clientID,
		cred)
	if err != nil {
		return confidential.AuthResult{}, fmt.Errorf("failed to create confidential client app: %w", err)
	}

	result, err := confidentialClientApp.AcquireTokenByCredential(ctx, []string{scope})
	if err != nil {
		return confidential.AuthResult{}, fmt.Errorf("failed to acquire AAD token: %w", err)
	}

	return result, nil
}

// readJWTFromFS reads the jwt from file system
// Source: https://github.com/Azure/azure-workload-identity/blob/d126293e3c7c669378b225ad1b1f29cf6af4e56d/examples/msal-go/token_credential.go#L88
func readJWTFromFS(tokenFilePath string) (string, error) {
	// #nosec G703 -- tokenFilePath is sourced from trusted Azure workload identity configuration, not user input.
	token, err := os.ReadFile(tokenFilePath)
	if err != nil {
		return "", err
	}
	return string(token), nil
}
