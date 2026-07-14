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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	paths "path/filepath"
	"time"

	oci "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	ocitarget "oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/errcode"
	"oras.land/oras-go/v2/registry/remote/retry"

	ratifyconfig "github.com/notaryproject/ratify/v2/config"
	re "github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/internal/logger"
	"github.com/notaryproject/ratify/v2/internal/version"
	"github.com/notaryproject/ratify/v2/pkg/cache"
	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/common/oras/authprovider"
	_ "github.com/notaryproject/ratify/v2/pkg/common/oras/authprovider/alibabacloud" // register alibabacloud auth provider
	_ "github.com/notaryproject/ratify/v2/pkg/common/oras/authprovider/aws"          // register aws auth provider
	_ "github.com/notaryproject/ratify/v2/pkg/common/oras/authprovider/azure"        // register azure auth provider
	commonutils "github.com/notaryproject/ratify/v2/pkg/common/utils"
	"github.com/notaryproject/ratify/v2/pkg/homedir"
	"github.com/notaryproject/ratify/v2/pkg/metrics"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore/config"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore/factory"
	"github.com/opencontainers/go-digest"
)

const (
	HTTPMaxIdleConns         = 100
	HTTPMaxConnsPerHost      = 100
	HTTPMaxIdleConnsPerHost  = 100
	HTTPRetryMax             = 5
	HTTPRetryDurationMinimum = 200 * time.Millisecond
	HTTPRetryDurationMax     = 1750 * time.Millisecond
)

const (
	storeName             = "oras"
	defaultLocalCachePath = "local_oras_cache"
	dockerConfigFileName  = "config.json"
	ratifyUserAgent       = "ratify"
)

var logOpt = logger.Option{ComponentType: logger.ReferrerStore}

// OrasStoreConf describes the configuration of ORAS store
type OrasStoreConf struct { //nolint:revive // ignore linter to have unique type name
	Name           string                          `json:"name"`
	UseHTTP        bool                            `json:"useHttp,omitempty"`
	CosignEnabled  bool                            `json:"cosignEnabled,omitempty"`
	AuthProvider   authprovider.AuthProviderConfig `json:"authProvider,omitempty"`
	LocalCachePath string                          `json:"localCachePath,omitempty"`
}

type orasStoreFactory struct{}

type orasStore struct {
	config             *OrasStoreConf
	rawConfig          config.StoreConfig
	localCache         content.Storage
	authProvider       authprovider.AuthProvider
	httpClient         *http.Client
	httpClientInsecure *http.Client
	createRepository   func(ctx context.Context, store *orasStore, targetRef common.Reference) (registry.Repository, error)
}

func init() {
	factory.Register(storeName, &orasStoreFactory{})
}

func (s *orasStoreFactory) Create(version string, storeConfig config.StorePluginConfig) (referrerstore.ReferrerStore, error) {
	storeBase, err := createBaseStore(version, storeConfig)
	if err != nil {
		return nil, err
	}

	if cache.GetCacheProvider() == nil {
		return storeBase, nil
	}

	cacheConf, err := toCacheConfig(storeBase.GetConfig().Store)
	if err != nil {
		return nil, re.ErrorCodeConfigInvalid.WithError(err).WithComponentType(re.ReferrerStore)
	}
	if !cacheConf.Enabled {
		return storeBase, nil
	}

	return createCachedStore(storeBase, cacheConf)
}

func createBaseStore(version string, storeConfig config.StorePluginConfig) (*orasStore, error) {
	conf := OrasStoreConf{}

	storeConfigBytes, err := json.Marshal(storeConfig)
	if err != nil {
		return nil, re.ErrorCodeConfigInvalid.WithError(err).WithComponentType(re.ReferrerStore)
	}

	if err := json.Unmarshal(storeConfigBytes, &conf); err != nil {
		return nil, re.ErrorCodeConfigInvalid.NewError(re.ReferrerStore, "", re.EmptyLink, err, "failed to parse oras store configuration", re.HideStackTrace)
	}

	authenticationProvider, err := authprovider.CreateAuthProviderFromConfig(conf.AuthProvider)
	if err != nil {
		return nil, re.ErrorCodePluginInitFailure.NewError(re.ReferrerStore, "", re.EmptyLink, err, "failed to create auth provider from configuration", re.HideStackTrace)
	}

	// Set up the local cache where content will land when we pull
	if conf.LocalCachePath == "" {
		conf.LocalCachePath = paths.Join(homedir.Get(), ratifyconfig.ConfigFileDir, defaultLocalCachePath)
	}

	localRegistry, err := ocitarget.New(conf.LocalCachePath)
	if err != nil {
		return nil, re.ErrorCodePluginInitFailure.WithError(err).WithComponentType(re.ReferrerStore).WithDetail(fmt.Sprintf("could not create local oras cache at path: %s", conf.LocalCachePath))
	}

	var customPredicate retry.Predicate = func(resp *http.Response, err error) (bool, error) {
		host := ""
		if resp != nil {
			if resp.Request != nil && resp.Request.URL != nil {
				host = resp.Request.URL.Host
			}
			metrics.ReportRegistryRequestCount(resp.Request.Context(), resp.StatusCode, host)
		}
		return retry.DefaultPredicate(resp, err)
	}

	customRetryPolicy := func() retry.Policy {
		return &retry.GenericPolicy{
			Retryable: customPredicate,
			Backoff:   retry.DefaultBackoff,
			MinWait:   HTTPRetryDurationMinimum,
			MaxWait:   HTTPRetryDurationMax,
			MaxRetry:  HTTPRetryMax,
		}
	}

	// define the http client for TLS enabled
	secureTransport := http.DefaultTransport.(*http.Transport).Clone()
	secureTransport.MaxIdleConns = HTTPMaxIdleConns
	secureTransport.MaxConnsPerHost = HTTPMaxConnsPerHost
	secureTransport.MaxIdleConnsPerHost = HTTPMaxIdleConnsPerHost
	secureRetryTransport := retry.NewTransport(secureTransport)
	secureRetryTransport.Policy = customRetryPolicy

	// define the http client for TLS disabled
	insecureTransport := http.DefaultTransport.(*http.Transport).Clone()
	insecureTransport.MaxIdleConns = HTTPMaxIdleConns
	insecureTransport.MaxConnsPerHost = HTTPMaxConnsPerHost
	insecureTransport.MaxIdleConnsPerHost = HTTPMaxIdleConnsPerHost
	// #nosec G402
	insecureTransport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
	}
	insecureRetryTransport := retry.NewTransport(insecureTransport)
	insecureRetryTransport.Policy = customRetryPolicy

	return &orasStore{config: &conf,
		rawConfig:          config.StoreConfig{Version: version, Store: storeConfig},
		localCache:         localRegistry,
		authProvider:       authenticationProvider,
		httpClient:         &http.Client{Transport: secureRetryTransport},
		httpClientInsecure: &http.Client{Transport: insecureRetryTransport},
		createRepository:   createDefaultRepository}, nil
}

func (store *orasStore) Name() string {
	return storeName
}

func (store *orasStore) GetConfig() *config.StoreConfig {
	return &store.rawConfig
}

func (store *orasStore) ListReferrers(ctx context.Context, subjectReference common.Reference, _ []string, _ string, subjectDesc *ocispecs.SubjectDescriptor) (referrerstore.ListReferrersResult, error) {
	repository, err := store.createRepository(ctx, store, subjectReference)
	if err != nil {
		return referrerstore.ListReferrersResult{}, re.ErrorCodeRepositoryOperationFailure.WithDetail("Failed to connect to the remote registry").WithError(err)
	}

	// resolve subject descriptor if not provided
	var resolvedSubjectDesc *ocispecs.SubjectDescriptor
	if subjectDesc != nil {
		resolvedSubjectDesc = subjectDesc
	} else {
		if resolvedSubjectDesc, err = store.GetSubjectDescriptor(ctx, subjectReference); err != nil {
			evictOnError(ctx, err, subjectReference.Original)
			return referrerstore.ListReferrersResult{}, err
		}
	}

	// find all referrers referencing subject descriptor
	artifactTypeFilter := ""
	var referrerDescriptors []oci.Descriptor
	if err := repository.Referrers(ctx, resolvedSubjectDesc.Descriptor, artifactTypeFilter, func(referrers []oci.Descriptor) error {
		referrerDescriptors = append(referrerDescriptors, referrers...)
		return nil
	}); err != nil && !errors.Is(err, errdef.ErrNotFound) {
		evictOnError(ctx, err, subjectReference.Original)
		return referrerstore.ListReferrersResult{}, err
	}

	// convert artifact descriptors to oci descriptor with artifact type
	referrers := []ocispecs.ReferenceDescriptor{}
	for _, referrer := range referrerDescriptors {
		referrers = append(referrers, OciDescriptorToReferenceDescriptor(referrer))
	}

	if store.config.CosignEnabled {
		// add cosign descriptor if exists
		cosignReferences, err := getCosignReferences(ctx, subjectReference, repository)
		if err != nil {
			return referrerstore.ListReferrersResult{}, err
		}

		if cosignReferences != nil {
			referrers = append(referrers, *cosignReferences...)
		}
	}

	return referrerstore.ListReferrersResult{Referrers: referrers}, nil
}

func (store *orasStore) GetBlobContent(ctx context.Context, subjectReference common.Reference, digest digest.Digest) ([]byte, error) {
	var err error
	var blobContent []byte

	repository, err := store.createRepository(ctx, store, subjectReference)
	if err != nil {
		return nil, re.ErrorCodeGetBlobContentFailure.WithDetail("Failed to connect to the remote registry").WithError(err)
	}

	// create a dummy Descriptor to check the local store cache
	blobDescriptor := oci.Descriptor{
		Digest: digest,
		Size:   0, // dummy size value
	}

	// check if blob exists in local ORAS cache
	isCached, err := store.localCache.Exists(ctx, blobDescriptor)
	if err != nil {
		logger.GetLogger(ctx, logOpt).Warnf("failed to check if blob [%s] exists in cache: %v", blobDescriptor.Digest.String(), err)
	}
	metrics.ReportBlobCacheCount(ctx, isCached)

	if isCached {
		blobContent, err = store.getRawContentFromCache(ctx, blobDescriptor)
		if err != nil {
			isCached = false
			logger.GetLogger(ctx, logOpt).Warnf("failed to get blob [%s] from cache: %v", blobDescriptor.Digest.String(), err)
		}
	}

	if !isCached {
		// generate the reference path with digest
		ref := fmt.Sprintf("%s@%s", subjectReference.Path, digest)

		// fetch blob content from remote repository
		blobDesc, rc, err := repository.Blobs().FetchReference(ctx, ref)
		if err != nil {
			evictOnError(ctx, err, subjectReference.Original)
			return nil, re.ErrorCodeRepositoryOperationFailure.WithDetail("Failed to fetch the artifact metadata from the registry").WithError(err)
		}
		if blobContent, err = io.ReadAll(rc); err != nil {
			return nil, re.ErrorCodeRepositoryOperationFailure.WithDetail("Failed to parse the artifact metadata").WithError(err)
		}

		// push fetched content to local ORAS cache
		// If multiple goroutines try to push the same blob to the cache, oras-go
		// may return `ErrAlreadyExists` error. This is expected and can be ignored.
		orasExistsExpectedError := fmt.Errorf("%s: %s: %w", blobDesc.Digest, blobDesc.MediaType, errdef.ErrAlreadyExists)
		if err = store.localCache.Push(ctx, blobDesc, bytes.NewReader(blobContent)); err != nil && err.Error() != orasExistsExpectedError.Error() {
			logger.GetLogger(ctx, logOpt).Warnf("failed to save blob [%s] in cache: %v", blobDesc.Digest, err)
		}
	}

	return blobContent, nil
}

func (store *orasStore) GetReferenceManifest(ctx context.Context, subjectReference common.Reference, referenceDesc ocispecs.ReferenceDescriptor) (ocispecs.ReferenceManifest, error) {
	repository, err := store.createRepository(ctx, store, subjectReference)
	if err != nil {
		return ocispecs.ReferenceManifest{}, re.ErrorCodeRepositoryOperationFailure.WithDetail("Failed to connect to the remote registry").WithError(err)
	}
	var manifestBytes []byte
	// check if manifest exists in local ORAS cache
	isCached, err := store.localCache.Exists(ctx, referenceDesc.Descriptor)
	if err != nil {
		logger.GetLogger(ctx, logOpt).Warnf("failed to check if manifest [%s] exists in cache: %v", referenceDesc.Descriptor.Digest, err)
	}
	metrics.ReportBlobCacheCount(ctx, isCached)

	if isCached {
		manifestBytes, err = store.getRawContentFromCache(ctx, referenceDesc.Descriptor)
		if err != nil {
			isCached = false
			logger.GetLogger(ctx, logOpt).Warnf("failed to get manifest [%s] from cache: %v", referenceDesc.Descriptor.Digest, err)
		}
	}

	if !isCached {
		// fetch manifest content from repository
		manifestReader, err := repository.Fetch(ctx, referenceDesc.Descriptor)
		if err != nil {
			evictOnError(ctx, err, subjectReference.Original)
			return ocispecs.ReferenceManifest{}, re.ErrorCodeRepositoryOperationFailure.WithDetail("Failed to fetch the artifact metadata from the registry").WithError(err)
		}

		manifestBytes, err = io.ReadAll(manifestReader)
		if err != nil {
			return ocispecs.ReferenceManifest{}, re.ErrorCodeManifestInvalid.WithDetail("Failed to parse the artifact metadata").WithError(err)
		}

		// push fetched manifest to local ORAS cache
		// If multiple goroutines try to push the same manifest to the cache, oras-go
		// may return `ErrAlreadyExists` error. This is expected and can be ignored.
		orasExistsExpectedError := fmt.Errorf("%s: %s: %w", referenceDesc.Descriptor.Digest, referenceDesc.Descriptor.MediaType, errdef.ErrAlreadyExists)
		err = store.localCache.Push(ctx, referenceDesc.Descriptor, bytes.NewReader(manifestBytes))
		if err != nil && err.Error() != orasExistsExpectedError.Error() {
			logger.GetLogger(ctx, logOpt).Warnf("failed to save manifest [%s] in cache: %v", referenceDesc.Descriptor.Digest, err)
		}
	}

	referenceManifest := ocispecs.ReferenceManifest{}

	// marshal manifest bytes into reference manifest descriptor
	if referenceDesc.Descriptor.MediaType == oci.MediaTypeImageManifest {
		var imageManifest oci.Manifest
		if err := json.Unmarshal(manifestBytes, &imageManifest); err != nil {
			return ocispecs.ReferenceManifest{}, re.ErrorCodeDataDecodingFailure.WithDetail("Failed to parse artifact metadata of mediatype `application/vnd.oci.image.manifest.v1+json`").WithError(err).WithRemediation("Please check if the artifact metadata was created correctly.")
		}
		referenceManifest = commonutils.OciManifestToReferenceManifest(imageManifest)
	} else if referenceDesc.Descriptor.MediaType == ocispecs.MediaTypeArtifactManifest {
		if err := json.Unmarshal(manifestBytes, &referenceManifest); err != nil {
			return ocispecs.ReferenceManifest{}, re.ErrorCodeDataDecodingFailure.WithDetail("Failed to parse artifact metadata of mediatype `application/vnd.oci.artifact.manifest.v1+json`").WithError(err).WithRemediation("Please check if the artifact metadata was created correctly.")
		}
	} else {
		return ocispecs.ReferenceManifest{}, re.ErrorCodeGetReferenceManifestFailure.WithDetail(fmt.Sprintf("Unsupported artifact metadata of media type %s", referenceDesc.Descriptor.MediaType)).WithRemediation("Please check if the artifact metadata was created correctly.")
	}

	return referenceManifest, nil
}

func (store *orasStore) GetSubjectDescriptor(ctx context.Context, subjectReference common.Reference) (*ocispecs.SubjectDescriptor, error) {
	repository, err := store.createRepository(ctx, store, subjectReference)
	if err != nil {
		return nil, re.ErrorCodeRepositoryOperationFailure.WithDetail("Failed to connect to remote registry").WithError(err)
	}

	desc, err := repository.Resolve(ctx, subjectReference.Original)
	if err != nil {
		evictOnError(ctx, err, subjectReference.Original)
		return nil, re.ErrorCodeRepositoryOperationFailure.WithDetail(fmt.Sprintf("Unable to resolve the reference: %s", subjectReference.Original)).WithError(err)
	}

	return &ocispecs.SubjectDescriptor{Descriptor: desc}, nil
}

// evict from cache on non retry-able errors including 401 and 403
func evictOnError(ctx context.Context, err error, subjectReference string) {
	cacheProvider := cache.GetCacheProvider()
	// if cache provider is not enabled, return
	if cacheProvider == nil {
		return
	}
	var ec *errcode.ErrorResponse

	if errors.As(err, &ec) && (ec.StatusCode == http.StatusForbidden || ec.StatusCode == http.StatusUnauthorized) {
		artifactRef, err := registry.ParseReference(subjectReference)
		if err != nil {
			logger.GetLogger(ctx, logOpt).Warnf("failed to evict credential from cache for %s: %v", subjectReference, err)
		}
		cacheProvider.Delete(ctx, fmt.Sprintf(cache.CacheKeyOrasAuth, artifactRef.Registry))
	}
}

func createDefaultRepository(ctx context.Context, store *orasStore, targetRef common.Reference) (registry.Repository, error) {
	if store.authProvider == nil || !store.authProvider.Enabled(ctx) {
		return nil, fmt.Errorf("auth provider not properly enabled")
	}
	artifactRef, err := registry.ParseReference(targetRef.Original)
	if err != nil {
		return nil, err
	}
	var authConfig authprovider.AuthConfig
	cacheProvider := cache.GetCacheProvider()
	var cacheResponse string
	found := false
	cacheHit := false
	if cacheProvider != nil {
		cacheResponse, found = cacheProvider.Get(ctx, fmt.Sprintf(cache.CacheKeyOrasAuth, artifactRef.Registry))
	}
	if cacheResponse != "" && found {
		if err := json.Unmarshal([]byte(cacheResponse), &authConfig); err != nil {
			logger.GetLogger(ctx, logOpt).Warn(re.ErrorCodeDataDecodingFailure.NewError(re.Cache, "", re.EmptyLink, err, fmt.Sprintf("failed to unmarshal auth config cache value: %s", cacheResponse), re.HideStackTrace))
		} else {
			logger.GetLogger(ctx, logOpt).Debug("auth cache hit")
			cacheHit = true
		}
	}
	if !cacheHit {
		logger.GetLogger(ctx, logOpt).Debug("auth cache miss")
		authConfig, err = store.authProvider.Provide(ctx, targetRef.Original)
		if err != nil {
			logger.GetLogger(ctx, logOpt).Warnf("auth provider failed with err, %v", err)
			logger.GetLogger(ctx, logOpt).Debug("attempting to use anonymous credentials")
		} else if authConfig == (authprovider.AuthConfig{}) {
			logger.GetLogger(ctx, logOpt).Debug("no credentials found, attempting to use anonymous credentials")
		} else {
			if cacheProvider != nil {
				success := cacheProvider.SetWithTTL(ctx, fmt.Sprintf(cache.CacheKeyOrasAuth, artifactRef.Registry), authConfig, time.Until(authConfig.ExpiresOn))
				if !success {
					logger.GetLogger(ctx, logOpt).Warn(re.ErrorCodeCacheNotSet.WithComponentType(re.Cache).WithDetail(fmt.Sprintf("failed to set auth cache for %s", artifactRef.Registry)))
				}
			}
		}
	}

	// create new ORAS repository target to the image/repository reference
	repository, err := remote.NewRepository(targetRef.Original)
	if err != nil {
		return nil, err
	}

	// set the provider to return the resolved credentials
	credentialProvider := func(_ context.Context, _ string) (auth.Credential, error) {
		if authConfig.Username != "" || authConfig.Password != "" || authConfig.IdentityToken != "" {
			return auth.Credential{
				Username:     authConfig.Username,
				Password:     authConfig.Password,
				RefreshToken: authConfig.IdentityToken,
			}, nil
		}
		return auth.EmptyCredential, nil
	}

	// set the repository client credentials
	repoClient := &auth.Client{
		Client:     store.httpClient,
		Header:     http.Header{},
		Cache:      auth.NewCache(),
		Credential: credentialProvider,
	}

	repoClient.SetUserAgent(version.UserAgent)
	repoClient.Header = logger.SetTraceIDHeader(ctx, repoClient.Header)

	// enable insecure if specified in config
	if isInsecureRegistry(targetRef.Original, store.config) {
		repoClient.Client = store.httpClientInsecure
	}

	repository.Client = repoClient
	// enable plain HTTP if specified in config
	repository.PlainHTTP = store.config.UseHTTP

	return repository, nil
}

func (store *orasStore) getRawContentFromCache(ctx context.Context, descriptor oci.Descriptor) ([]byte, error) {
	reader, err := store.localCache.Fetch(ctx, descriptor)
	if err != nil {
		return nil, err
	}

	buf, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return buf, nil
}
