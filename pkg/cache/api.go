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

package cache

import (
	"context"
	"time"
)

const (
	CacheKeySubjectDescriptor string = "cache_ratify_subject_descriptor_%s"
	CacheKeyListReferrers     string = "cache_ratify_list_referrers_%s"
	CacheKeyVerifyHandler     string = "cache_ratify_verify_handler_%s"
	CacheKeyOrasAuth          string = "cache_ratify_oras_auth_%s"

	DefaultCacheType string = "ristretto"
	// DefaultCacheTTL is the default time-to-live for the cache entry.
	DefaultCacheTTL time.Duration = 10 * time.Second
	// DefaultCacheName is the default endpoint for the cache. Only used for dapr currently.
	DefaultCacheName string = "dapr-redis"
	// DefaultCacheSize is the default size of the cache in MB. Only used for ristretto currently.
	DefaultCacheSize int = 256
)

type CacheProvider interface { //nolint:revive // ignore linter to have unique type name
	// Get returns the string, json-marshalled value linked to key. Returns true/false for existence
	Get(ctx context.Context, key string) (string, bool)

	// Set adds value based on key to cache. Assume there will be no ttl. Returns true/false for success
	Set(ctx context.Context, key string, value interface{}) bool

	// SetWithTTL adds value based on key to cache. Ties ttl of entry to ttl provided. Returns true/false for success
	SetWithTTL(ctx context.Context, key string, value interface{}, ttl time.Duration) bool

	// Delete removes the specified key/value from the cache
	Delete(ctx context.Context, key string) bool
}
