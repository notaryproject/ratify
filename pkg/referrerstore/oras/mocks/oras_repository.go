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

package mocks

import (
	"context"
	"io"

	"github.com/opencontainers/go-digest"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"
)

type TestRepository struct {
	registry.Repository
	ResolveErr    error
	ResolveMap    map[string]oci.Descriptor
	ReferrersList []oci.Descriptor
	FetchMap      map[digest.Digest]io.ReadCloser
	BlobStoreTest TestBlobStore
}

type TestBlobStore struct {
	registry.BlobStore
	BlobMap map[string]BlobPair
}

type BlobPair struct {
	Descriptor oci.Descriptor
	Reader     io.ReadCloser
}

func (r TestRepository) Resolve(_ context.Context, reference string) (oci.Descriptor, error) {
	if r.ResolveErr != nil {
		return oci.Descriptor{}, r.ResolveErr
	}
	if desc, ok := r.ResolveMap[reference]; ok {
		return desc, nil
	}
	return oci.Descriptor{}, errdef.ErrNotFound
}

func (r TestRepository) Referrers(_ context.Context, _ oci.Descriptor, _ string, fn func(referrers []oci.Descriptor) error) error {
	return fn(r.ReferrersList)
}

func (r TestRepository) Fetch(_ context.Context, target oci.Descriptor) (io.ReadCloser, error) {
	if reader, ok := r.FetchMap[target.Digest]; ok {
		return reader, nil
	}
	return nil, errdef.ErrNotFound
}

func (r TestRepository) Blobs() registry.BlobStore {
	return r.BlobStoreTest
}

func (b TestBlobStore) FetchReference(_ context.Context, reference string) (oci.Descriptor, io.ReadCloser, error) {
	if pair, ok := b.BlobMap[reference]; ok {
		return pair.Descriptor, pair.Reader, nil
	}
	return oci.Descriptor{}, nil, errdef.ErrNotFound
}
