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
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/notaryproject/ratify/v2/pkg/cache"
	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore/config"
	"github.com/opencontainers/go-digest"

	oci "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	testName = "testName"
)

var (
	ttl          = 3
	base         = &mockBase{}
	pluginConfig = map[string]interface{}{
		"cacheEnabled": true,
		"ttl":          ttl,
	}
	pluginConfigTTL = map[string]interface{}{
		"cacheEnabled": true,
	}
	conf = &cacheConf{
		Enabled: true,
		TTL:     ttl,
	}
	configNoTTL = &cacheConf{
		Enabled: true,
		TTL:     10,
	}
	testStoreConfig = &config.StoreConfig{}
	testBlob        = make([]byte, 0)
	testDigest      = digest.Digest("sha256:123456")
	testReference   = common.Reference{
		Path:   "testRegistry/testRepo",
		Digest: testDigest,
	}
	testDesc    = &ocispecs.SubjectDescriptor{Descriptor: oci.Descriptor{Digest: testDigest}}
	testResult1 = referrerstore.ListReferrersResult{
		Referrers: []ocispecs.ReferenceDescriptor{
			{
				Descriptor: oci.Descriptor{
					Digest: testDigest,
				},
			},
		},
	}
	testResult2 = referrerstore.ListReferrersResult{
		NextToken: testNextToken2,
	}
	testNextToken1 = "1"
	testNextToken2 = "2"
)

type mockBase struct{}

func (m *mockBase) Name() string {
	return testName
}

func (m *mockBase) GetConfig() *config.StoreConfig {
	return testStoreConfig
}

func (m *mockBase) ListReferrers(_ context.Context, _ common.Reference, _ []string, nextToken string, _ *ocispecs.SubjectDescriptor) (referrerstore.ListReferrersResult, error) {
	if nextToken == testNextToken1 {
		return testResult1, nil
	} else if nextToken == testNextToken2 {
		return testResult2, nil
	}
	return referrerstore.ListReferrersResult{}, nil
}

func (m *mockBase) GetBlobContent(_ context.Context, _ common.Reference, _ digest.Digest) ([]byte, error) {
	return testBlob, nil
}

func (m *mockBase) GetReferenceManifest(_ context.Context, _ common.Reference, _ ocispecs.ReferenceDescriptor) (ocispecs.ReferenceManifest, error) {
	return ocispecs.ReferenceManifest{}, nil
}

func (m *mockBase) GetSubjectDescriptor(_ context.Context, _ common.Reference) (*ocispecs.SubjectDescriptor, error) {
	return testDesc, nil
}

func TestCreateCachedStore(t *testing.T) {
	if _, err := createCachedStore(base, conf); err != nil {
		t.Fatalf("expect no error, got %v", err)
	}
}

func TestName(t *testing.T) {
	store, _ := createCachedStore(base, conf)

	name := store.Name()
	if name != testName {
		t.Fatalf("expect name: %s, got %s", testName, name)
	}
}

func TestGetConfig(t *testing.T) {
	store, _ := createCachedStore(base, conf)

	conf := store.GetConfig()
	if !reflect.DeepEqual(conf, testStoreConfig) {
		t.Fatalf("expect config: %+v, got %+v", testStoreConfig, conf)
	}
}

func TestGetBlobContent(t *testing.T) {
	store, _ := createCachedStore(base, conf)

	blob, err := store.GetBlobContent(context.Background(), testReference, testDigest)
	if err != nil {
		t.Fatalf("expect no error, got %v", err)
	}
	if !reflect.DeepEqual(blob, testBlob) {
		t.Fatalf("expect blob: %v, got %v", testBlob, blob)
	}
}

func TestGetSubjectDescriptor_CacheProviderNil(t *testing.T) {
	store, err := createCachedStore(base, conf)
	if err != nil {
		t.Fatalf("expect no error, got %v", err)
	}
	_, err = store.GetSubjectDescriptor(context.Background(), testReference)
	if err != nil {
		t.Fatalf("expected no error, but got %v", err)
	}
}

func TestListReferrers_CacheProviderNil(t *testing.T) {
	store, err := createCachedStore(base, conf)
	if err != nil {
		t.Fatalf("expect no error, got %v", err)
	}
	_, err = store.ListReferrers(context.Background(), testReference, nil, "", nil)
	if err != nil {
		t.Fatalf("expected no error, but got %v", err)
	}
}

func TestGetSubjectDescriptor_Cache(t *testing.T) {
	var err error
	ctx := context.Background()
	store, _ := createCachedStore(base, conf)
	cacheProvider := cache.GetCacheProvider()
	if cacheProvider == nil {
		// if no cache provider has been initialized, initialize one
		cacheProvider, err = cache.NewCacheProvider(ctx, cache.DefaultCacheType, cache.DefaultCacheName, cache.DefaultCacheSize)
		if err != nil {
			t.Errorf("Expected no error, but got %v", err)
		}
	}

	// GetSubjectDescriptor should populate cache and return test descriptor
	desc, err := store.GetSubjectDescriptor(ctx, testReference)
	if err != nil {
		t.Fatalf("err should be nil, but got %v", err)
	}

	if !reflect.DeepEqual(desc, testDesc) {
		t.Fatalf("expect desc: %+v, got %+v", testDesc, desc)
	}

	time.Sleep(1 * time.Second) // wait for cache to populate

	// check cache directly to make sure key exists
	_, exists := cacheProvider.Get(ctx, fmt.Sprintf(cache.CacheKeySubjectDescriptor, testDigest))
	if !exists {
		t.Fatalf("cache key should exist")
	}

	// override cache to different value
	newDesc := ocispecs.SubjectDescriptor{Descriptor: oci.Descriptor{Digest: "sha256:654321"}}
	isSuccess := cacheProvider.Set(ctx, fmt.Sprintf(cache.CacheKeySubjectDescriptor, testDigest), newDesc)
	if !isSuccess {
		t.Fatalf("cache set should succeed")
	}

	// check returned value matches new value
	desc, err = store.GetSubjectDescriptor(ctx, testReference)
	if err != nil {
		t.Fatalf("err should be nil, but got %v", err)
	}

	if !reflect.DeepEqual(desc, &newDesc) {
		t.Fatalf("expect desc: %+v, got %+v", &newDesc, desc)
	}
}

func TestListReferrers_CacheHit(t *testing.T) {
	store, _ := createCachedStore(base, conf)
	var err error
	ctx := context.Background()
	cacheProvider := cache.GetCacheProvider()
	if cacheProvider == nil {
		// if no cache provider has been initialized, initialize one
		_, err = cache.NewCacheProvider(ctx, cache.DefaultCacheType, cache.DefaultCacheName, cache.DefaultCacheSize)
		if err != nil {
			t.Errorf("Expected no error, but got %v", err)
		}
	}

	result, _ := store.ListReferrers(ctx, testReference, []string{}, testNextToken1, nil)

	time.Sleep(time.Duration(ttl-2) * time.Second)

	cachedResult, err := store.ListReferrers(ctx, testReference, []string{}, testNextToken2, nil)
	if err != nil {
		t.Fatalf("err should be nil, but got %v", err)
	}
	if !reflect.DeepEqual(result, cachedResult) {
		t.Fatalf("cached result: %+v is different from result: %+v", cachedResult, result)
	}
}

func TestListReferrers_CacheMiss(t *testing.T) {
	store, _ := createCachedStore(base, conf)
	var err error
	ctx := context.Background()
	cacheProvider := cache.GetCacheProvider()
	if cacheProvider == nil {
		// if no cache provider has been initialized, initialize one
		_, err = cache.NewCacheProvider(ctx, cache.DefaultCacheType, cache.DefaultCacheName, cache.DefaultCacheSize)
		if err != nil {
			t.Errorf("Expected no error, but got %v", err)
		}
	}

	result, _ := store.ListReferrers(ctx, testReference, []string{}, testNextToken1, nil)

	time.Sleep(time.Duration(ttl+2) * time.Second)

	cachedResult, err := store.ListReferrers(ctx, testReference, []string{}, testNextToken2, nil)
	if err != nil {
		t.Fatalf("err should be nil, but got %v", err)
	}
	if reflect.DeepEqual(result, cachedResult) {
		t.Fatalf("cached result: %+v should be different from result: %+v", cachedResult, result)
	}
}

func TestToCacheConfig(t *testing.T) {
	resultCache, err := toCacheConfig(pluginConfig)
	if err != nil {
		t.Fatalf("expect no error, got %v", err)
	}
	if !reflect.DeepEqual(conf, resultCache) {
		t.Fatalf("expect %v, got %v", conf, resultCache)
	}
	// test TTL is set to default 10 seconds
	resultCache, err = toCacheConfig(pluginConfigTTL)
	if err != nil {
		t.Fatalf("expect no error, got %v", err)
	}
	if !reflect.DeepEqual(configNoTTL, resultCache) {
		t.Fatalf("expect %v, got %v", conf, resultCache)
	}
}
