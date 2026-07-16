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
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
)

type TestStorage struct {
	content.Storage
	ExistsMap map[digest.Digest]io.Reader
	ExistsErr error
	FetchErr  error
	PushErr   error
}

func (s TestStorage) Exists(_ context.Context, target oci.Descriptor) (bool, error) {
	if s.ExistsErr != nil {
		return false, s.ExistsErr
	}
	if _, ok := s.ExistsMap[target.Digest]; ok {
		return true, nil
	}
	return false, nil
}

func (s TestStorage) Push(_ context.Context, expected oci.Descriptor, content io.Reader) error {
	if s.PushErr != nil {
		return s.PushErr
	}
	s.ExistsMap[expected.Digest] = content
	return nil
}

func (s TestStorage) Fetch(_ context.Context, target oci.Descriptor) (io.ReadCloser, error) {
	if s.FetchErr != nil {
		return nil, s.FetchErr
	}
	if reader, ok := s.ExistsMap[target.Digest]; ok {
		return io.NopCloser(reader), nil
	}
	return nil, errdef.ErrNotFound
}
