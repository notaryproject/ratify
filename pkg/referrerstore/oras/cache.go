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

package oras

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/internal/logger"
	"github.com/notaryproject/ratify/v2/pkg/cache"
	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
)

const defaultTTL = 10

type orasStoreWithInMemoryCache struct {
	referrerstore.ReferrerStore
	cacheConf *cacheConf
}

type cacheConf struct {
	Enabled bool `json:"cacheEnabled"`
	TTL     int  `json:"ttl"`
}

// createCachedStore creates a new oras store decorated with in-memory cache to cache
// results of ListReferrers API.
func createCachedStore(storeBase referrerstore.ReferrerStore, cacheConf *cacheConf) (referrerstore.ReferrerStore, error) {
	return &orasStoreWithInMemoryCache{
		ReferrerStore: storeBase,
		cacheConf:     cacheConf,
	}, nil
}

func (store *orasStoreWithInMemoryCache) ListReferrers(ctx context.Context, subjectReference common.Reference, artifactTypes []string, nextToken string, subjectDesc *ocispecs.SubjectDescriptor) (referrerstore.ListReferrersResult, error) {
	var err error
	var result referrerstore.ListReferrersResult
	cacheKey := fmt.Sprintf(cache.CacheKeyListReferrers, subjectReference.Original)
	cacheProvider := cache.GetCacheProvider()
	if cacheProvider == nil {
		logger.GetLogger(ctx, logOpt).Warnf("failed to get cache provider")
	} else {
		val, found := cacheProvider.Get(ctx, cacheKey)
		if val != "" && found {
			if err = json.Unmarshal([]byte(val), &result); err != nil {
				logger.GetLogger(ctx, logOpt).Warn(errors.ErrorCodeDataDecodingFailure.NewError(errors.Cache, "", errors.EmptyLink, err, fmt.Sprintf("failed to unmarshal cache value for key %s: %s", cacheKey, val), errors.HideStackTrace))
			} else {
				logger.GetLogger(ctx, logOpt).Debug("cache hit for list referrers")
				return result, nil
			}
		}
	}
	logger.GetLogger(ctx, logOpt).Debugf("list referrers cache miss for value: %s", subjectReference.Original)
	result, err = store.ReferrerStore.ListReferrers(ctx, subjectReference, artifactTypes, nextToken, subjectDesc)
	if err == nil {
		if cacheProvider != nil {
			if added := cacheProvider.SetWithTTL(ctx, cacheKey, result, time.Duration(store.cacheConf.TTL)*time.Second); !added { // TODO: convert ttl to duration in helm values
				logger.GetLogger(ctx, logOpt).Warnf("failed to add cache with key: %+v, val: %+v", cacheKey, result)
			}
		}
	}

	return result, err
}

func (store *orasStoreWithInMemoryCache) GetSubjectDescriptor(ctx context.Context, subjectReference common.Reference) (*ocispecs.SubjectDescriptor, error) {
	result := &ocispecs.SubjectDescriptor{}
	var err error
	cacheProvider := cache.GetCacheProvider()
	if cacheProvider == nil {
		logger.GetLogger(ctx, logOpt).Warnf("failed to get cache provider")
	} else {
		val, found := cacheProvider.Get(ctx, fmt.Sprintf(cache.CacheKeySubjectDescriptor, subjectReference.Digest))
		if val != "" && found {
			if err = json.Unmarshal([]byte(val), result); err != nil {
				logger.GetLogger(ctx, logOpt).Warn(errors.ErrorCodeDataDecodingFailure.NewError(errors.Cache, "", errors.EmptyLink, err, fmt.Sprintf("failed to unmarshal cache value: %v", val), errors.HideStackTrace))
			} else {
				logger.GetLogger(ctx, logOpt).Debug("cache hit for subject descriptor")
				return result, nil
			}
		}
	}
	logger.GetLogger(ctx, logOpt).Debugf("subject descriptor cache miss for value: %s", subjectReference.Original)
	result, err = store.ReferrerStore.GetSubjectDescriptor(ctx, subjectReference)
	if err == nil {
		if cacheProvider != nil {
			cacheKey := fmt.Sprintf(cache.CacheKeySubjectDescriptor, result.Digest)
			if added := cacheProvider.Set(ctx, cacheKey, *result); !added {
				logger.GetLogger(ctx, logOpt).Warnf("failed to add cache with key: %+v, val: %+v", cacheKey, result)
			}
		}
	}

	return result, err
}

func toCacheConfig(storePluginConfig map[string]interface{}) (*cacheConf, error) {
	bytes, err := json.Marshal(storePluginConfig)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling store plugin config: %+v to bytes, err: %w", storePluginConfig, err)
	}

	cacheConf := &cacheConf{}
	if err := json.Unmarshal(bytes, cacheConf); err != nil {
		return nil, fmt.Errorf("failed unmarshalling to Oras cache config, err: %w", err)
	}

	if cacheConf.TTL == 0 {
		cacheConf.TTL = defaultTTL
	}

	return cacheConf, nil
}
