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

// Package builtin registers the plugins that are shipped with Ratify to the
// default plugin registry of github.com/notaryproject/ratify-go/plugin. Import
// it for its side effects:
//
//	import _ "github.com/notaryproject/ratify/v2/pkg/builtin"
package builtin

import (
	// Register policy enforcers
	_ "github.com/notaryproject/ratify/v2/internal/policyenforcer/threshold" // Register threshold policy enforcer

	// Register stores
	_ "github.com/notaryproject/ratify/v2/internal/store/filesystemocistore" // Register the filesystem OCI store
	_ "github.com/notaryproject/ratify/v2/internal/store/registrystore"      // Register the registry store

	// Register credential providers
	_ "github.com/notaryproject/ratify/v2/internal/store/credentialprovider/alibabacloud" // Register the Alibaba Cloud ACR credential provider factory
	_ "github.com/notaryproject/ratify/v2/internal/store/credentialprovider/aws"          // Register the AWS ECR credential provider factory
	_ "github.com/notaryproject/ratify/v2/internal/store/credentialprovider/azure"        // Register the Azure credential provider factory
	_ "github.com/notaryproject/ratify/v2/internal/store/credentialprovider/static"       // Register the static credential provider factory

	// Register verifiers
	_ "github.com/notaryproject/ratify-verifier-go/cosign/register"   // Register the Cosign verifier
	_ "github.com/notaryproject/ratify-verifier-go/notation/register" // Register the Notation verifier

	// Register key providers
	_ "github.com/notaryproject/ratify/v2/internal/verifier/keyprovider/azurekeyvault"      // Register the Azure Key Vault key provider
	_ "github.com/notaryproject/ratify/v2/internal/verifier/keyprovider/filesystemprovider" // Register the filesystem key provider
	_ "github.com/notaryproject/ratify/v2/internal/verifier/keyprovider/inlineprovider"     // Register the inline key provider
)
