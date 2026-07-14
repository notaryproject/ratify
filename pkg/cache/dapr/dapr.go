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

package dapr

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/dapr/go-sdk/client"
	ctxUtils "github.com/notaryproject/ratify/v2/internal/context"
	"github.com/notaryproject/ratify/v2/internal/logger"
	"github.com/notaryproject/ratify/v2/pkg/cache"
	"github.com/notaryproject/ratify/v2/pkg/featureflag"
)

const DaprCacheType = "dapr"

var logOpt = logger.Option{
	ComponentType: logger.Cache,
}

type factory struct{}

type daprCache struct {
	daprClient client.Client
	cacheName  string
}

func init() {
	cache.Register(DaprCacheType, &factory{})
}

func (factory *factory) Create(_ context.Context, cacheName string, _ int) (cache.CacheProvider, error) {
	if !featureflag.HighAvailability.Enabled {
		return nil, fmt.Errorf("Dapr cache provider is not enabled. Please set the environment variable RATIFY_EXPERIMENTAL_HIGH_AVAILABILITY to enable it")
	}
	daprClient, err := client.NewClient()
	if err != nil {
		return nil, err
	}

	return &daprCache{
		daprClient: daprClient,
		cacheName:  cacheName,
	}, nil
}

func (d *daprCache) Get(ctx context.Context, key string) (string, bool) {
	item, err := d.daprClient.GetState(ctx, d.cacheName, ctxUtils.CreateCacheKey(ctx, key), nil)
	if err != nil {
		return "", false
	}
	return string(item.Value), true
}

func (d *daprCache) Set(ctx context.Context, key string, value interface{}) bool {
	bytes, err := json.Marshal(value)
	if err != nil {
		logger.GetLogger(ctx, logOpt).Error("Error marshalling value for redis: ", err)
		return false
	}
	if err := d.daprClient.SaveState(ctx, d.cacheName, ctxUtils.CreateCacheKey(ctx, key), bytes, nil); err != nil {
		logger.GetLogger(ctx, logOpt).Error("Error saving value to redis: ", err)
		return false
	}
	return true
}

func (d *daprCache) SetWithTTL(ctx context.Context, key string, value interface{}, ttl time.Duration) bool {
	if ttl < 0 {
		logger.GetLogger(ctx, logOpt).Errorf("Error saving value to redis: ttl provided must be >= 0: %v", ttl)
		return false
	}
	bytes, err := json.Marshal(value)
	if err != nil {
		logger.GetLogger(ctx, logOpt).Error("Error marshalling value for redis: ", err)
		return false
	}
	ttlString := strconv.Itoa(int(ttl.Seconds()))
	md := map[string]string{"ttlInSeconds": ttlString}
	if err := d.daprClient.SaveState(ctx, d.cacheName, ctxUtils.CreateCacheKey(ctx, key), bytes, md); err != nil {
		logger.GetLogger(ctx, logOpt).Error("Error saving value to redis: ", err)
		return false
	}
	return true
}

func (d *daprCache) Delete(ctx context.Context, key string) bool {
	if err := d.daprClient.DeleteState(ctx, d.cacheName, ctxUtils.CreateCacheKey(ctx, key), nil); err != nil {
		logger.GetLogger(ctx, logOpt).Error("Error deleting value from redis: ", err)
		return false
	}
	return true
}
