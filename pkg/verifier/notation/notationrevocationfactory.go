// Copyright The Ratify Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package notation

import (
	"net/http"
	"sync"

	"github.com/notaryproject/notation-core-go/revocation"
	corecrl "github.com/notaryproject/notation-core-go/revocation/crl"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/ratify/v2/config"
	re "github.com/notaryproject/ratify/v2/errors"
)

type CRLHandler struct {
	CacheEnabled bool
	httpClient   *http.Client
}

var (
	fetcherOnce   sync.Once
	globalFetcher corecrl.Fetcher
)

// CreateCRLHandlerFromConfig creates a new instance of CRLHandler using the configuration
// provided in config.CRLConf. It returns a RevocationFactory interface.
// The CRLHandler will have its CacheDisabled field set based on the configuration,
// and it will use a default HTTP client.
func CreateCRLHandlerFromConfig() RevocationFactory {
	return &CRLHandler{CacheEnabled: config.CRLConf.Cache.Enabled, httpClient: &http.Client{}}
}

// NewFetcher creates a new instance of a Fetcher if it doesn't already exist.
// If a Fetcher instance is already present, it returns the existing instance.
// The method also configures the cache for the Fetcher.
// Returns an instance of corecrl.Fetcher or an error if the Fetcher creation fails.
func (h *CRLHandler) NewFetcher() (corecrl.Fetcher, error) {
	var err error
	fetcherOnce.Do(func() {
		globalFetcher, err = CreateCRLFetcher(h.httpClient, dir.PathCRLCache)
	})
	if err != nil {
		return nil, err
	}
	// Check if the fetcher is nil, return an error if it is.
	// one possible edge case is that an error happened in the first call,
	// the following calls will not get the error since the sync.Once block will be skipped.
	if globalFetcher == nil {
		return nil, re.ErrorCodeConfigInvalid.WithDetail("failed to create CRL fetcher")
	}
	return globalFetcher, nil
}

// NewValidator returns a new validator instance
func (h *CRLHandler) NewValidator(opts revocation.Options) (revocation.Validator, error) {
	return revocation.NewWithOptions(opts)
}
