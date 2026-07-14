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

package controllers

import (
	cs "github.com/notaryproject/ratify/v2/pkg/customresources/certificatestores"
	"github.com/notaryproject/ratify/v2/pkg/customresources/policies"
	rs "github.com/notaryproject/ratify/v2/pkg/customresources/referrerstores"
	"github.com/notaryproject/ratify/v2/pkg/customresources/verifiers"
)

var (
	// NamespacedVerifiers is a map between namespace and verifiers.
	NamespacedVerifiers = verifiers.NewActiveVerifiers()

	// NamespacedPolicies is the active policy generated from CRD. There would be exactly
	// one active policy belonging to a namespace at any given time.
	NamespacedPolicies = policies.NewActivePolicies()

	// NamespacedStores is a map to track active stores across namespaces.
	NamespacedStores = rs.NewActiveStores()

	// NamespacedCertStores is a map between namespace and CertificateStores.
	NamespacedCertStores = cs.NewActiveCertStores()
)
