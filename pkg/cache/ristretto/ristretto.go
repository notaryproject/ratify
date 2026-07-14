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

package ristretto

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/dgraph-io/ristretto"
	"github.com/dgraph-io/ristretto/z"
	ctxUtils "github.com/notaryproject/ratify/v2/internal/context"
	"github.com/notaryproject/ratify/v2/internal/logger"
	"github.com/notaryproject/ratify/v2/pkg/cache"
)

const RistrettoCacheType = "ristretto"

var logOpt = logger.Option{
	ComponentType: logger.Cache,
}

type factory struct {
	once sync.Once
}

type ristrettoCache struct {
	memoryCache *ristretto.Cache
}

func init() {
	cache.Register(RistrettoCacheType, &factory{})
}

func (f *factory) Create(ctx context.Context, _ string, cacheSize int) (cache.CacheProvider, error) {
	var err error
	var memoryCache *ristretto.Cache
	f.once.Do(func() {
		memoryCache, err = ristretto.NewCache(&ristretto.Config{
			NumCounters: int64(cacheSize) * 5000,        // number of keys to track frequency. Assumes 5000 keys per MB.
			MaxCost:     int64(cacheSize) * 1024 * 1024, // Max size in Megabytes.
			BufferItems: 64,                             // number of keys per Get buffer. 64 is recommended by the ristretto library.
			KeyToHash:   keyToHash,
		})
	})
	if err != nil {
		logger.GetLogger(ctx, logOpt).Errorf("could not create cache, err: %v", err)
		return &ristrettoCache{}, err
	}

	return &ristrettoCache{
		memoryCache: memoryCache,
	}, nil
}

func (r *ristrettoCache) Get(ctx context.Context, key string) (string, bool) {
	cacheValue, found := r.memoryCache.Get(ctxUtils.CreateCacheKey(ctx, key))
	if !found {
		return "", false
	}
	returnValue, ok := cacheValue.(string)
	return returnValue, ok
}

func (r *ristrettoCache) Set(ctx context.Context, key string, value interface{}) bool {
	bytes, err := json.Marshal(value)
	if err != nil {
		logger.GetLogger(ctx, logOpt).Error("Error marshalling value for ristretto: ", err)
		return false
	}
	return r.memoryCache.Set(ctxUtils.CreateCacheKey(ctx, key), string(bytes), 1)
}

func (r *ristrettoCache) SetWithTTL(ctx context.Context, key string, value interface{}, ttl time.Duration) bool {
	if ttl < 0 {
		logger.GetLogger(ctx, logOpt).Errorf("Error saving value to ristretto: ttl provided must be >= 0: %v", ttl)
		return false
	}
	bytes, err := json.Marshal(value)
	if err != nil {
		logger.GetLogger(ctx, logOpt).Error("Error marshalling value for ristretto: ", err)
		return false
	}
	return r.memoryCache.SetWithTTL(ctxUtils.CreateCacheKey(ctx, key), string(bytes), 1, ttl)
}

func (r *ristrettoCache) Delete(ctx context.Context, key string) bool {
	r.memoryCache.Del(ctxUtils.CreateCacheKey(ctx, key))
	// Note: ristretto does not return a bool for delete.
	// Delete ops are eventually consistent and we don't want to block on them.
	return true
}

func keyToHash(key interface{}) (uint64, uint64) {
	if key == nil {
		return 0, 0
	}
	switch k := key.(type) {
	case string:
		return z.MemHashString(k), xxhash.Sum64String(k)
	default:
		return 0, 0
	}
}
