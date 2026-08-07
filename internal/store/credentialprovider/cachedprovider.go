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

package credentialprovider

import (
	"context"
	"errors"
	"time"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify/v2/internal/cache"
	"github.com/notaryproject/ratify/v2/internal/cache/inmemory"
	"github.com/notaryproject/ratify/v2/internal/logger"
)

var logOpt = logger.Option{ComponentType: logger.AuthProvider}

// CredentialWithTTL represents a credential response with its expiration time.
type CredentialWithTTL struct {
	Credential ratify.RegistryCredential
	TTL        time.Duration
}

// CredentialSourceProvider is an interface for credential providers that return
// credentials with TTL information. This is the interface that actual credential
// providers (Azure, AWS, etc.) should implement.
type CredentialSourceProvider interface {
	GetWithTTL(ctx context.Context, serverAddress string) (CredentialWithTTL, error)
}

// CachedProvider wraps a CredentialSourceProvider and provides caching functionality.
// It implements the ratify.RegistryCredentialGetter interface.
type CachedProvider struct {
	source CredentialSourceProvider
	cache  cache.Cache[ratify.RegistryCredential]
}

// NewCachedProvider creates a new cached credential provider that wraps the given source provider.
func NewCachedProvider(source CredentialSourceProvider) (*CachedProvider, error) {
	cache, err := inmemory.NewCache[ratify.RegistryCredential](10)
	if err != nil {
		return nil, err
	}

	return &CachedProvider{
		source: source,
		cache:  cache,
	}, nil
}

// Get implements ratify.RegistryCredentialGetter interface.
// It returns cached credentials if available and not expired, otherwise fetches
// new credentials from the source provider and caches them.
func (c *CachedProvider) Get(ctx context.Context, serverAddress string) (ratify.RegistryCredential, error) {
	log := logger.GetLogger(ctx, logOpt)
	// Check if we have a cached credential
	credential, err := c.cache.Get(ctx, serverAddress)
	switch {
	case err == nil:
		log.Debugf("registry credential cache hit for %s", serverAddress)
		return credential, nil
	case errors.Is(err, cache.ErrNotFound):
		log.Debugf("registry credential cache miss for %s", serverAddress)
	default:
		// Not a plain miss: the cache itself is unhealthy, which is worth
		// surfacing because every request now pays the full credential exchange.
		log.Warnf("failed to read the registry credential cache for %s: %v", serverAddress, err)
	}

	// Cache miss, fetch new credentials
	credWithTTL, err := c.source.GetWithTTL(ctx, serverAddress)
	if err != nil {
		return ratify.RegistryCredential{}, err
	}

	if credWithTTL.TTL > 0 {
		defer func() {
			if err := c.cache.Set(ctx, serverAddress, credWithTTL.Credential, credWithTTL.TTL); err != nil {
				log.Warnf("failed to cache the registry credential for %s: %v", serverAddress, err)
				return
			}
			log.Debugf("cached the registry credential for %s for %s", serverAddress, credWithTTL.TTL)
		}()
	} else {
		log.Debugf("registry credential for %s has no TTL and will not be cached", serverAddress)
	}
	return credWithTTL.Credential, nil
}
