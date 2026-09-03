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

package registrystore

import (
	"context"
	"time"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify/v2/internal/logger"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

var logOpt = logger.Option{ComponentType: logger.ReferrerStore}

// loggingStore reports every registry operation the executor performs.
// ratify-go's RegistryStore is deliberately dependency-free and does not log, so
// without this wrapper a slow or failing registry call leaves no trace at all.
type loggingStore struct {
	inner ratify.Store
}

func (s *loggingStore) Resolve(ctx context.Context, ref string) (ocispec.Descriptor, error) {
	log := logger.GetLogger(ctx, logOpt)
	start := time.Now()
	desc, err := s.inner.Resolve(ctx, ref)
	if err != nil {
		log.Errorf("failed to resolve %s after %dms: %v", ref, time.Since(start).Milliseconds(), err)
		return desc, err
	}
	log.Debugf("resolved %s to %s in %dms", ref, desc.Digest, time.Since(start).Milliseconds())
	return desc, nil
}

func (s *loggingStore) ListReferrers(ctx context.Context, ref string, artifactTypes []string, fn func(referrers []ocispec.Descriptor) error) error {
	log := logger.GetLogger(ctx, logOpt)
	start := time.Now()
	// ListReferrers paginates, so the total is only known once fn stops being called.
	count := 0
	err := s.inner.ListReferrers(ctx, ref, artifactTypes, func(referrers []ocispec.Descriptor) error {
		count += len(referrers)
		return fn(referrers)
	})
	if err != nil {
		log.Errorf("failed to list referrers for %s after %dms: %v", ref, time.Since(start).Milliseconds(), err)
		return err
	}
	log.Debugf("listed %d referrer(s) for %s in %dms", count, ref, time.Since(start).Milliseconds())
	return nil
}

func (s *loggingStore) FetchBlob(ctx context.Context, repo string, desc ocispec.Descriptor) ([]byte, error) {
	log := logger.GetLogger(ctx, logOpt)
	start := time.Now()
	blob, err := s.inner.FetchBlob(ctx, repo, desc)
	if err != nil {
		log.Errorf("failed to fetch blob %s from %s after %dms: %v", desc.Digest, repo, time.Since(start).Milliseconds(), err)
		return nil, err
	}
	log.Debugf("fetched blob %s (%s, %d bytes) from %s in %dms", desc.Digest, desc.MediaType, len(blob), repo, time.Since(start).Milliseconds())
	return blob, nil
}

func (s *loggingStore) FetchManifest(ctx context.Context, repo string, desc ocispec.Descriptor) ([]byte, error) {
	log := logger.GetLogger(ctx, logOpt)
	start := time.Now()
	manifest, err := s.inner.FetchManifest(ctx, repo, desc)
	if err != nil {
		log.Errorf("failed to fetch manifest %s from %s after %dms: %v", desc.Digest, repo, time.Since(start).Milliseconds(), err)
		return nil, err
	}
	log.Debugf("fetched manifest %s (%s, %d bytes) from %s in %dms", desc.Digest, desc.MediaType, len(manifest), repo, time.Since(start).Milliseconds())
	return manifest, nil
}
