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
	"time"

	"github.com/ratify-project/ratify/internal/logger"
)

const (
	dockerTokenLoginUsernameGUID               = "00000000-0000-0000-0000-000000000000"
	AADResource                                = "https://containerregistry.azure.net/.default"
	defaultACRExpiryDuration     time.Duration = 3 * time.Hour
	defaultACREndpoint                         = "*.azurecr.io"
)

var (
	logOpt = logger.Option{
		ComponentType: logger.AuthProvider,
	}
	defaultACREndpoints = []string{"*.azurecr.io", "*.azurecr.us", "*.azurecr.cn"}
)
