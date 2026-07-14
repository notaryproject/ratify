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

package refresh

import (
	"context"

	"github.com/notaryproject/ratify/v2/pkg/keymanagementprovider"
)

const (
	KubeRefresherType = "kubeRefresher"
)

// Refresher is an interface that defines methods to be implemented by a each refresher
type Refresher interface {
	// Refresh is a method that refreshes the certificates/keys
	Refresh(ctx context.Context) error
	// GetResult is a method that returns the result of the refresh
	GetResult() interface{}
	// GetStatus is a method that returns the status of the refresh
	GetStatus() interface{}
}

// RefresherConfig is a struct that holds the configuration for a refresher
type RefresherConfig struct {
	RefresherType           string                                      // RefresherType is the type of the refresher
	Provider                keymanagementprovider.KeyManagementProvider // Provider is the key management provider
	ProviderType            string                                      // ProviderType is the type of the provider
	ProviderRefreshInterval string                                      // ProviderRefreshInterval is the refresh interval for the provider
	Resource                string                                      // Resource is the resource to be refreshed
}
