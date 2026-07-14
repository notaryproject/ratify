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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/notaryproject/ratify/v2/pkg/cache"
	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore/config"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore/oras/mocks"
	"github.com/opencontainers/go-digest"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

const (
	inputOriginalPath       = "localhost:5000/net-monitor:v0"
	wrongReferenceMediatype = "application/vnd.oci.image.manifest.wrong.v1+json"
	validReferenceMediatype = "application/vnd.oci.image.manifest.right.v1+json"
)

var (
	artifactDigestNotCached          = digest.FromString("testArtifactDigestNotCached")
	artifactDigest                   = digest.FromString("testArtifactDigest")
	invalidManifestBytes             = []byte("invalid manifest")
	blobDigest                       = digest.FromString("testBlobDigest")
	firstDigest                      = digest.FromString("testDigest")
	manifestNotCachedBytes           []byte
	manifestCachedBytesWithWrongType []byte
	manifestCachedBytes              []byte
)

func init() {
	manifestNotCached := oci.Manifest{
		MediaType: validReferenceMediatype,
		Config:    oci.Descriptor{},
		Layers:    []oci.Descriptor{},
	}
	manifestNotCachedBytes, _ = json.Marshal(manifestNotCached)

	manifestCachedWithWrongType := oci.Manifest{
		MediaType: wrongReferenceMediatype,
		Config:    oci.Descriptor{},
		Layers:    []oci.Descriptor{},
	}
	manifestCachedBytesWithWrongType, _ = json.Marshal(manifestCachedWithWrongType)

	manifestCached := oci.Manifest{
		MediaType: validReferenceMediatype,
		Config:    oci.Descriptor{},
		Layers:    []oci.Descriptor{},
	}
	manifestCachedBytes, _ = json.Marshal(manifestCached)
}

type errorReader struct{}

func (r *errorReader) Read(_ []byte) (int, error) {
	return 0, errors.New("error reading")
}

func (r *errorReader) Close() error {
	return nil
}

// TestORASName tests the Name method of the oras store.
func TestORASName(t *testing.T) {
	conf := config.StorePluginConfig{
		"name": "oras",
	}
	store, err := createBaseStore("1.0.0", conf)
	if err != nil {
		t.Fatalf("failed to create oras store: %v", err)
	}
	output := store.Name()
	if output != "oras" {
		t.Fatalf("expected name to be 'oras', got '%s'", output)
	}
}

// TestORASGetConfig tests the GetConfig method of the oras store.
func TestORASGetConfig(t *testing.T) {
	conf := config.StorePluginConfig{
		"name": "oras",
	}
	expectedRawConfig := config.StoreConfig{Version: "1.0.0", Store: conf}
	store, err := createBaseStore("1.0.0", conf)
	if err != nil {
		t.Fatalf("failed to create oras store: %v", err)
	}
	output := store.GetConfig()
	if !reflect.DeepEqual(*output, expectedRawConfig) {
		t.Fatalf("expected raw config to be %v, got %v", expectedRawConfig, output)
	}
}

func TestORASListReferrers_SubjectDesc(t *testing.T) {
	conf := config.StorePluginConfig{
		"name":          "oras",
		"cosignEnabled": false,
	}
	ctx := context.Background()
	subjectDigest := digest.FromString("testDigest")
	referrerDigest := digest.FromString("testArtifactDigest")
	store, err := createBaseStore("1.0.0", conf)
	if err != nil {
		t.Fatalf("failed to create oras store: %v", err)
	}
	subjectDesc := ocispecs.SubjectDescriptor{
		Descriptor: oci.Descriptor{
			Digest: subjectDigest,
		},
	}
	testRepo := mocks.TestRepository{
		ResolveMap: map[string]oci.Descriptor{
			inputOriginalPath: subjectDesc.Descriptor,
		},
		ReferrersList: []oci.Descriptor{
			{
				Digest:       referrerDigest,
				ArtifactType: "application/vnd.cncf.notary.signature",
			},
		},
	}
	store.createRepository = func(_ context.Context, _ *orasStore, _ common.Reference) (registry.Repository, error) {
		return testRepo, nil
	}
	inputRef := common.Reference{
		Original: inputOriginalPath,
		Digest:   subjectDigest,
	}
	referrers, err := store.ListReferrers(ctx, inputRef, []string{}, "", &subjectDesc)
	if err != nil {
		t.Fatalf("failed to list referrers: %v", err)
	}

	if referrers.NextToken != "" {
		t.Fatalf("expected next token to be empty, got %s", referrers.NextToken)
	}

	if len(referrers.Referrers) != 1 {
		t.Fatalf("expected 1 referrer, got %d", len(referrers.Referrers))
	}

	if referrers.Referrers[0].Digest != referrerDigest {
		t.Fatalf("expected digest %s, got %s", referrerDigest, referrers.Referrers[0].Digest)
	}

	if referrers.Referrers[0].ArtifactType != "application/vnd.cncf.notary.signature" {
		t.Fatalf("expected artifact type %s, got %s", "application/vnd.cncf.notary.signature", referrers.Referrers[0].ArtifactType)
	}
}

func TestORASListReferrers_NoSubjectDesc(t *testing.T) {
	conf := config.StorePluginConfig{
		"name":          "oras",
		"cosignEnabled": false,
	}
	ctx := context.Background()
	subjectDigest := digest.FromString("testDigest")
	referrerDigest := digest.FromString("testArtifactDigest")
	store, err := createBaseStore("1.0.0", conf)
	if err != nil {
		t.Fatalf("failed to create oras store: %v", err)
	}
	subjectDesc := ocispecs.SubjectDescriptor{
		Descriptor: oci.Descriptor{
			Digest: subjectDigest,
		},
	}
	testRepo := mocks.TestRepository{
		ResolveMap: map[string]oci.Descriptor{
			inputOriginalPath: subjectDesc.Descriptor,
		},
		ReferrersList: []oci.Descriptor{
			{
				Digest:       referrerDigest,
				ArtifactType: "application/vnd.cncf.notary.signature",
			},
		},
	}
	store.createRepository = func(_ context.Context, _ *orasStore, _ common.Reference) (registry.Repository, error) {
		return testRepo, nil
	}
	inputRef := common.Reference{
		Original: inputOriginalPath,
		Digest:   subjectDigest,
	}
	referrers, err := store.ListReferrers(ctx, inputRef, []string{}, "", nil)
	if err != nil {
		t.Fatalf("failed to list referrers: %v", err)
	}

	if referrers.NextToken != "" {
		t.Fatalf("expected next token to be empty, got %s", referrers.NextToken)
	}

	if len(referrers.Referrers) != 1 {
		t.Fatalf("expected 1 referrer, got %d", len(referrers.Referrers))
	}

	if referrers.Referrers[0].Digest != referrerDigest {
		t.Fatalf("expected digest %s, got %s", referrerDigest, referrers.Referrers[0].Digest)
	}

	if referrers.Referrers[0].ArtifactType != "application/vnd.cncf.notary.signature" {
		t.Fatalf("expected artifact type %s, got %s", "application/vnd.cncf.notary.signature", referrers.Referrers[0].ArtifactType)
	}
}

// TODO: add cosign test for List Referrers

func TestORASGetReferenceManifest(t *testing.T) {
	tests := []struct {
		name              string
		inputRef          common.Reference
		referenceDesc     ocispecs.ReferenceDescriptor
		repo              registry.Repository
		repoCreateErr     error
		localCache        content.Storage
		expectedErr       bool
		expectedMediaType string
	}{
		{
			name: "cache exists failure",
			inputRef: common.Reference{
				Original: "inputOriginalPath",
				Digest:   firstDigest,
			},
			referenceDesc: ocispecs.ReferenceDescriptor{
				Descriptor: oci.Descriptor{
					MediaType: ocispecs.MediaTypeArtifactManifest,
					Digest:    artifactDigest,
				},
			},
			repo: mocks.TestRepository{
				FetchMap: map[digest.Digest]io.ReadCloser{},
			},
			localCache: mocks.TestStorage{
				ExistsErr: errors.New("cache exists error"),
			},
			expectedErr: true,
		},
		{
			name: "cache fetch manifest failure",
			inputRef: common.Reference{
				Original: inputOriginalPath,
				Digest:   firstDigest,
			},
			referenceDesc: ocispecs.ReferenceDescriptor{
				Descriptor: oci.Descriptor{
					MediaType: ocispecs.MediaTypeArtifactManifest,
					Digest:    artifactDigest,
				},
			},
			repo: mocks.TestRepository{
				FetchMap: map[digest.Digest]io.ReadCloser{
					artifactDigest: io.NopCloser(bytes.NewReader(manifestNotCachedBytes)),
				},
			},
			localCache: mocks.TestStorage{
				ExistsMap: map[digest.Digest]io.Reader{
					artifactDigest: bytes.NewReader(manifestCachedBytes),
				},
				FetchErr: errors.New("cache fetch error"),
			},
			expectedErr:       false,
			expectedMediaType: validReferenceMediatype,
		},
		{
			name: "not cached desc and fetch failed",
			inputRef: common.Reference{
				Original: inputOriginalPath,
				Digest:   firstDigest,
			},
			referenceDesc: ocispecs.ReferenceDescriptor{
				Descriptor: oci.Descriptor{
					MediaType: ocispecs.MediaTypeArtifactManifest,
					Digest:    artifactDigest,
				},
			},
			repo: mocks.TestRepository{
				FetchMap: map[digest.Digest]io.ReadCloser{},
			},
			localCache: mocks.TestStorage{
				ExistsMap: map[digest.Digest]io.Reader{
					artifactDigestNotCached: bytes.NewReader(manifestCachedBytesWithWrongType),
				},
			},
			expectedErr: true,
		},
		{
			name:          "create repository failed",
			inputRef:      common.Reference{},
			referenceDesc: ocispecs.ReferenceDescriptor{},
			repo:          mocks.TestRepository{},
			repoCreateErr: errors.New("create repository error"),
			expectedErr:   true,
		},
		{
			name: "reference manifest is returned from the cache if it exists",
			inputRef: common.Reference{
				Original: inputOriginalPath,
				Digest:   firstDigest,
			},
			referenceDesc: ocispecs.ReferenceDescriptor{
				Descriptor: oci.Descriptor{
					MediaType: ocispecs.MediaTypeArtifactManifest,
					Digest:    artifactDigest,
				},
			},
			repo: mocks.TestRepository{
				FetchMap: map[digest.Digest]io.ReadCloser{
					artifactDigest: io.NopCloser(bytes.NewReader(manifestNotCachedBytes)),
				},
			},
			localCache: mocks.TestStorage{
				ExistsMap: map[digest.Digest]io.Reader{
					artifactDigest: bytes.NewReader(manifestCachedBytes),
				},
			},
			expectedErr:       false,
			expectedMediaType: validReferenceMediatype,
		},
		{
			name: "reference manifest is fetched from the registry if it is not cached",
			inputRef: common.Reference{
				Original: inputOriginalPath,
				Digest:   firstDigest,
			},
			referenceDesc: ocispecs.ReferenceDescriptor{
				Descriptor: oci.Descriptor{
					MediaType: ocispecs.MediaTypeArtifactManifest,
					Digest:    artifactDigest,
				},
			},
			repo: mocks.TestRepository{
				FetchMap: map[digest.Digest]io.ReadCloser{
					artifactDigest: io.NopCloser(bytes.NewReader(manifestNotCachedBytes)),
				},
			},
			localCache: mocks.TestStorage{
				ExistsMap: map[digest.Digest]io.Reader{
					artifactDigestNotCached: bytes.NewReader(manifestCachedBytesWithWrongType),
				},
			},
			expectedErr:       false,
			expectedMediaType: validReferenceMediatype,
		},
		{
			name: "descriptor not cached and fail during io.ReadAll from manifest",
			inputRef: common.Reference{
				Original: inputOriginalPath,
				Digest:   firstDigest,
			},
			referenceDesc: ocispecs.ReferenceDescriptor{
				Descriptor: oci.Descriptor{
					MediaType: ocispecs.MediaTypeArtifactManifest,
					Digest:    artifactDigest,
				},
			},
			repo: mocks.TestRepository{
				FetchMap: map[digest.Digest]io.ReadCloser{
					artifactDigest: &errorReader{},
				},
			},
			localCache: mocks.TestStorage{
				FetchErr: errors.New("cache fetch error"),
			},
			expectedErr: true,
		},
		{
			name: "failed to unmarshal to oci manifest",
			inputRef: common.Reference{
				Original: inputOriginalPath,
				Digest:   firstDigest,
			},
			referenceDesc: ocispecs.ReferenceDescriptor{
				Descriptor: oci.Descriptor{
					MediaType: oci.MediaTypeImageManifest,
					Digest:    artifactDigest,
				},
			},
			repo: mocks.TestRepository{
				FetchMap: map[digest.Digest]io.ReadCloser{
					artifactDigest: io.NopCloser(bytes.NewReader(invalidManifestBytes)),
				},
			},
			localCache: mocks.TestStorage{
				ExistsMap: map[digest.Digest]io.Reader{
					artifactDigestNotCached: bytes.NewReader(manifestCachedBytesWithWrongType),
				},
			},
			expectedErr: true,
		},
		{
			name: "failed to unmarshal to artifact manifest",
			inputRef: common.Reference{
				Original: inputOriginalPath,
				Digest:   firstDigest,
			},
			referenceDesc: ocispecs.ReferenceDescriptor{
				Descriptor: oci.Descriptor{
					MediaType: ocispecs.MediaTypeArtifactManifest,
					Digest:    artifactDigest,
				},
			},
			repo: mocks.TestRepository{
				FetchMap: map[digest.Digest]io.ReadCloser{
					artifactDigest: io.NopCloser(bytes.NewReader(invalidManifestBytes)),
				},
			},
			localCache: mocks.TestStorage{
				ExistsMap: map[digest.Digest]io.Reader{
					artifactDigestNotCached: bytes.NewReader(manifestCachedBytesWithWrongType),
				},
			},
			expectedErr: true,
		},
		{
			name: "unsupported manifest media type",
			inputRef: common.Reference{
				Original: inputOriginalPath,
				Digest:   firstDigest,
			},
			referenceDesc: ocispecs.ReferenceDescriptor{
				Descriptor: oci.Descriptor{
					MediaType: "unsupported media type",
					Digest:    artifactDigest,
				},
			},
			repo: mocks.TestRepository{
				FetchMap: map[digest.Digest]io.ReadCloser{
					artifactDigest: io.NopCloser(bytes.NewReader(invalidManifestBytes)),
				},
			},
			localCache: mocks.TestStorage{
				ExistsMap: map[digest.Digest]io.Reader{
					artifactDigestNotCached: bytes.NewReader(manifestCachedBytesWithWrongType),
				},
			},
			expectedErr: true,
		},
		{
			name: "failed to push manifest to cache",
			inputRef: common.Reference{
				Original: inputOriginalPath,
				Digest:   firstDigest,
			},
			referenceDesc: ocispecs.ReferenceDescriptor{
				Descriptor: oci.Descriptor{
					MediaType: ocispecs.MediaTypeArtifactManifest,
					Digest:    artifactDigest,
				},
			},
			repo: mocks.TestRepository{
				FetchMap: map[digest.Digest]io.ReadCloser{
					artifactDigest: io.NopCloser(bytes.NewReader(manifestNotCachedBytes)),
				},
			},
			localCache: mocks.TestStorage{
				ExistsMap: map[digest.Digest]io.Reader{
					artifactDigestNotCached: bytes.NewReader(manifestCachedBytesWithWrongType),
				},
				PushErr: errors.New("push content error"),
			},
			expectedErr:       false,
			expectedMediaType: validReferenceMediatype,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conf := config.StorePluginConfig{
				"name": "oras",
			}
			store, err := createBaseStore("1.0.0", conf)
			if err != nil {
				t.Fatalf("failed to create oras store: %v", err)
			}
			store.createRepository = func(_ context.Context, _ *orasStore, _ common.Reference) (registry.Repository, error) {
				return tc.repo, tc.repoCreateErr
			}
			store.localCache = tc.localCache

			manifest, err := store.GetReferenceManifest(context.Background(), tc.inputRef, tc.referenceDesc)
			if tc.expectedErr {
				if err == nil {
					t.Fatalf("expected error fetching reference manifest")
				}
			} else {
				if err != nil {
					t.Fatalf("failed to get reference manifest: %v", err)
				}
				if manifest.MediaType != tc.expectedMediaType {
					t.Fatalf("expected media type %s, got %s", tc.expectedMediaType, manifest.MediaType)
				}
			}
		})
	}
}

func TestORASGetBlobContent(t *testing.T) {
	tests := []struct {
		name             string
		repo             registry.Repository
		localCache       content.Storage
		repoCreateErr    error
		subjectReference common.Reference
		digest           digest.Digest
		expectedContent  []byte
		expectedErr      bool
	}{
		{
			name:          "fail to create repository",
			repo:          mocks.TestRepository{},
			repoCreateErr: errors.New("create repository error"),
			expectedErr:   true,
		},
		{
			name: "fail to check blob existence",
			repo: mocks.TestRepository{
				BlobStoreTest: mocks.TestBlobStore{
					BlobMap: map[string]mocks.BlobPair{
						fmt.Sprintf("%s@%s", inputOriginalPath, blobDigest.String()): {
							Descriptor: oci.Descriptor{
								Digest: blobDigest,
							},
							Reader: io.NopCloser(bytes.NewReader([]byte("test content"))),
						},
					},
				},
			},
			localCache: mocks.TestStorage{
				ExistsMap: map[digest.Digest]io.Reader{},
				ExistsErr: errors.New("check blob existence error"),
			},
			subjectReference: common.Reference{
				Original: inputOriginalPath,
				Path:     inputOriginalPath,
				Digest:   firstDigest,
			},
			digest:          blobDigest,
			expectedContent: []byte("test content"),
			expectedErr:     false,
		},
		{
			name: "fail to get raw content from cache",
			repo: mocks.TestRepository{
				BlobStoreTest: mocks.TestBlobStore{
					BlobMap: map[string]mocks.BlobPair{
						fmt.Sprintf("%s@%s", inputOriginalPath, blobDigest.String()): {
							Descriptor: oci.Descriptor{
								Digest: blobDigest,
							},
							Reader: io.NopCloser(bytes.NewReader([]byte("test content"))),
						},
					},
				},
			},
			localCache: mocks.TestStorage{
				ExistsMap: map[digest.Digest]io.Reader{
					blobDigest: bytes.NewReader([]byte("test content")),
				},
				FetchErr: errors.New("fetch blob error"),
			},
			subjectReference: common.Reference{
				Original: inputOriginalPath,
				Path:     inputOriginalPath,
				Digest:   firstDigest,
			},
			digest:          blobDigest,
			expectedContent: []byte("test content"),
			expectedErr:     false,
		},
		{
			name: "fail to fetch blob from repository",
			repo: mocks.TestRepository{
				BlobStoreTest: mocks.TestBlobStore{
					BlobMap: map[string]mocks.BlobPair{},
				},
			},
			localCache: mocks.TestStorage{
				ExistsMap: map[digest.Digest]io.Reader{},
			},
			subjectReference: common.Reference{
				Original: inputOriginalPath,
				Path:     inputOriginalPath,
				Digest:   firstDigest,
			},
			digest:      blobDigest,
			expectedErr: true,
		},
		{
			name: "fail to read fetched blob",
			repo: mocks.TestRepository{
				BlobStoreTest: mocks.TestBlobStore{
					BlobMap: map[string]mocks.BlobPair{
						fmt.Sprintf("%s@%s", inputOriginalPath, blobDigest.String()): {
							Descriptor: oci.Descriptor{
								Digest: blobDigest,
							},
							Reader: &errorReader{},
						},
					},
				},
			},
			localCache: mocks.TestStorage{
				ExistsMap: map[digest.Digest]io.Reader{},
			},
			subjectReference: common.Reference{
				Original: inputOriginalPath,
				Path:     inputOriginalPath,
				Digest:   firstDigest,
			},
			digest:      blobDigest,
			expectedErr: true,
		},
		{
			name: "fail to push content to local cache",
			repo: mocks.TestRepository{
				BlobStoreTest: mocks.TestBlobStore{
					BlobMap: map[string]mocks.BlobPair{
						fmt.Sprintf("%s@%s", inputOriginalPath, blobDigest.String()): {
							Descriptor: oci.Descriptor{
								Digest: blobDigest,
							},
							Reader: io.NopCloser(bytes.NewReader([]byte("test content"))),
						},
					},
				},
			},
			localCache: mocks.TestStorage{
				ExistsMap: map[digest.Digest]io.Reader{},
				PushErr:   errors.New("push content error"),
			},
			subjectReference: common.Reference{
				Original: inputOriginalPath,
				Path:     inputOriginalPath,
				Digest:   firstDigest,
			},
			digest:          blobDigest,
			expectedContent: []byte("test content"),
			expectedErr:     false,
		},
		{
			name: "blob content is fetched from the cache if it is cached",
			repo: mocks.TestRepository{
				BlobStoreTest: mocks.TestBlobStore{
					BlobMap: map[string]mocks.BlobPair{
						fmt.Sprintf("%s@%s", inputOriginalPath, blobDigest.String()): {
							Descriptor: oci.Descriptor{
								Digest: blobDigest,
							},
							Reader: io.NopCloser(bytes.NewReader([]byte("test content"))),
						},
					},
				},
			},
			localCache: mocks.TestStorage{
				ExistsMap: map[digest.Digest]io.Reader{
					blobDigest: bytes.NewReader([]byte("test content")),
				},
			},
			subjectReference: common.Reference{
				Original: inputOriginalPath,
				Path:     inputOriginalPath,
				Digest:   firstDigest,
			},
			digest:          blobDigest,
			expectedContent: []byte("test content"),
			expectedErr:     false,
		},
		{
			name: "blob content is fetched from the registry if it is not cached",
			repo: mocks.TestRepository{
				BlobStoreTest: mocks.TestBlobStore{
					BlobMap: map[string]mocks.BlobPair{
						fmt.Sprintf("%s@%s", inputOriginalPath, blobDigest.String()): {
							Descriptor: oci.Descriptor{
								Digest: blobDigest,
							},
							Reader: io.NopCloser(bytes.NewReader([]byte("test content"))),
						},
					},
				},
			},
			localCache: mocks.TestStorage{
				ExistsMap: map[digest.Digest]io.Reader{},
			},
			subjectReference: common.Reference{
				Original: inputOriginalPath,
				Path:     inputOriginalPath,
				Digest:   firstDigest,
			},
			digest:          blobDigest,
			expectedContent: []byte("test content"),
			expectedErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := config.StorePluginConfig{
				"name": "oras",
			}
			store, err := createBaseStore("1.0.0", conf)
			if err != nil {
				t.Fatalf("failed to create oras store: %v", err)
			}
			store.createRepository = func(_ context.Context, _ *orasStore, _ common.Reference) (registry.Repository, error) {
				return tt.repo, tt.repoCreateErr
			}
			store.localCache = tt.localCache
			content, err := store.GetBlobContent(context.Background(), tt.subjectReference, tt.digest)
			if tt.expectedErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				if !bytes.Equal(content, tt.expectedContent) {
					t.Fatalf("expected content %s, got %s", tt.expectedContent, content)
				}
			}
		})
	}
}

func Test_EvictOnError(t *testing.T) {
	ctx := context.Background()
	var err error

	cacheProvider := cache.GetCacheProvider()
	if cacheProvider == nil {
		// if no cache provider has been initialized, initialize one
		cacheProvider, err = cache.NewCacheProvider(ctx, cache.DefaultCacheType, cache.DefaultCacheName, cache.DefaultCacheSize)
		if err != nil {
			t.Errorf("Expected no error, but got %v", err)
		}
	}

	testcases := []struct {
		Method           string
		StatusCode       int
		subjectReference string
	}{
		{
			Method:     "GET",
			StatusCode: 401,
		},
		{
			Method:     "GET",
			StatusCode: 403,
		},
	}

	for _, testcase := range testcases {
		subjectReference := "testSubjectRef"
		cacheKey := fmt.Sprintf(cache.CacheKeyOrasAuth, subjectReference)
		cacheProvider.Set(ctx, cacheKey, "hello")
		time.Sleep(1 * time.Second)
		// validate the entry exists
		_, ok := cacheProvider.Get(ctx, cacheKey)
		if !ok {
			t.Fatalf("failed to add entry to auth cache")
		}

		mockErrResponse := errcode.ErrorResponse{
			Method:     testcase.Method,
			StatusCode: testcase.StatusCode,
		}
		evictOnError(ctx, &mockErrResponse, subjectReference+"/test")
		time.Sleep(1 * time.Second)
		// validate the entry should no longer exist
		_, ok = cacheProvider.Get(ctx, cacheKey)
		if ok {
			t.Fatalf("Auth cache entry should have been evicted")
		}
	}
}

// Test_ORASRetryClient tests that the retry client retries on 429 for specified number of retries
func Test_ORASRetryClient(t *testing.T) {
	// Create a test server
	count := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead && r.URL.Path == "/v2/test/manifests/latest":
			w.WriteHeader(http.StatusTooManyRequests)
			count++
			return
		default:
			w.WriteHeader(http.StatusForbidden)
		}
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	conf := config.StorePluginConfig{
		"name":    "oras",
		"useHttp": true,
	}
	store, err := createBaseStore("1.0.0", conf)
	if err != nil {
		t.Fatalf("failed to create oras store: %v", err)
	}
	uri, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("invalid test http server: %v", err)
	}
	_, err = store.GetSubjectDescriptor(context.Background(), common.Reference{
		Original: uri.Host + "/test:latest",
		Tag:      "latest",
		Path:     uri.Host + "/test",
	})
	if err != nil {
		var ec errcode.Error
		if errors.As(err, &ec) && (ec.Code != fmt.Sprint(http.StatusTooManyRequests)) {
			t.Fatalf("expected error code %d, got %s", http.StatusTooManyRequests, ec.Code)
		}
	}

	// Verify that the retry client was used by checking the number of retries
	// The retry client will retry 5 times, so we expect 6 total requests
	if count != 6 {
		t.Fatalf("expected 6 retries, got %d", count)
	}
}

func TestORASCreate_CreateBaseStore_Failure(t *testing.T) {
	conf := config.StorePluginConfig{
		"name": "oras",
		"authProvider": map[string]interface{}{
			"name": "mock",
		},
	}
	factory := orasStoreFactory{}
	_, err := factory.Create("1.0.0", conf)
	if err == nil {
		t.Fatalf("expected error creating oras store")
	}
}
func TestORASCreate_CacheProvider_Nil(t *testing.T) {
	conf := config.StorePluginConfig{
		"name": "oras",
	}
	factory := orasStoreFactory{}
	store, err := factory.Create("1.0.0", conf)
	if err != nil {
		t.Fatalf("failed to create oras store: %v", err)
	}
	if _, ok := store.(*orasStore); !ok {
		t.Fatalf("expected oras store")
	}
}
