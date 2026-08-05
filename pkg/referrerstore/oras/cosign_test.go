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
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	ratifyerrors "github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/pkg/cache"
	_ "github.com/notaryproject/ratify/v2/pkg/cache/ristretto"
	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore/oras/mocks"
	"github.com/opencontainers/go-digest"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

func TestAttachedImageTag(t *testing.T) {
	getDigest := func(dig string) digest.Digest {
		dg, _ := digest.Parse(dig)
		return dg
	}
	testcases := []struct {
		input  common.Reference
		output string
		err    error
	}{
		{
			input: common.Reference{
				Path:   "localhost:5000/net-monitor",
				Tag:    "v1",
				Digest: getDigest("sha256:a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb"),
			},
			output: "localhost:5000/net-monitor:sha256-a0fc570a245b09ed752c42d600ee3bb5b4f77bbd70d8898780b7ab43454530eb.sig",
			err:    nil,
		},
		{
			input: common.Reference{
				Path: "localhost:5000/net-monitor",
				Tag:  "v1",
			},
			err: ratifyerrors.ErrorCodeReferenceInvalid.WithDetail(""),
		},
	}

	for _, testcase := range testcases {
		mutated, err := attachedImageTag(testcase.input, CosignSignatureTagSuffix)
		if err != nil && !errors.Is(err, testcase.err) {
			t.Fatalf("expected error to be %v, but got %v", testcase.err, err)
		}
		if mutated != testcase.output {
			t.Fatalf("expected image tag to be %s, but got %s", testcase.output, mutated)
		}
	}
}

func TestGetCosignReferences(t *testing.T) {
	ctx := context.Background()
	var err error
	// first attempt to get the cache provider if it's already been initialized
	cacheProvider := cache.GetCacheProvider()
	if cacheProvider == nil {
		// if no cache provider has been initialized, initialize one
		_, err = cache.NewCacheProvider(ctx, cache.DefaultCacheType, cache.DefaultCacheName, cache.DefaultCacheSize)
		if err != nil {
			t.Errorf("Expected no error, but got %v", err)
		}
	}
	nonStandardError := errors.New("non-standard error")
	forbiddenError := &errcode.ErrorResponse{StatusCode: http.StatusForbidden, Errors: []errcode.Error{{Code: "FORBIDDEN"}}}
	unauthorizedError := &errcode.ErrorResponse{StatusCode: http.StatusUnauthorized, Errors: []errcode.Error{{Code: "UNAUTHORIZED"}}}
	testSubjectDigest := digest.FromString("test")
	testCosignSubjectTag := fmt.Sprintf("%s-%s.sig", testSubjectDigest.Algorithm().String(), testSubjectDigest.Hex())
	testCosignImageDigest := digest.FromString("test_cosign")
	testcases := []struct {
		name       string
		subjectRef common.Reference
		repository registry.Repository
		output     *[]ocispecs.ReferenceDescriptor
		err        error
	}{
		{
			name: "no subject digest",
			subjectRef: common.Reference{
				Path: "localhost:5000/net-monitor",
				Tag:  "v1",
			},
			repository: mocks.TestRepository{},
			output:     nil,
			err:        ratifyerrors.ErrorCodeReferenceInvalid.WithDetail(""),
		},
		{
			name: "no cosign references",
			subjectRef: common.Reference{
				Path:   "localhost:5000/net-monitor",
				Tag:    "v1",
				Digest: testSubjectDigest,
			},
			repository: mocks.TestRepository{
				ResolveMap: map[string]oci.Descriptor{
					fmt.Sprintf("localhost:5000/net-monitor-not-found:%s", testCosignSubjectTag): {
						Digest: testCosignImageDigest,
					},
				},
			},
			output: nil,
			err:    nil,
		},
		{
			name: "one cosign reference",
			subjectRef: common.Reference{
				Path:   "localhost:5000/net-monitor",
				Tag:    "v1",
				Digest: testSubjectDigest,
			},
			repository: mocks.TestRepository{
				ResolveMap: map[string]oci.Descriptor{
					fmt.Sprintf("localhost:5000/net-monitor:%s", testCosignSubjectTag): {
						Digest: testCosignImageDigest,
					},
				},
			},
			output: &[]ocispecs.ReferenceDescriptor{
				{
					Descriptor: oci.Descriptor{
						Digest: testCosignImageDigest,
					},
					ArtifactType: CosignArtifactType,
				},
			},
			err: nil,
		},
		{
			name: "resolve error non-standard error code",
			subjectRef: common.Reference{
				Path:   "localhost:5000/net-monitor",
				Tag:    "v1",
				Digest: testSubjectDigest,
			},
			repository: mocks.TestRepository{
				ResolveErr: nonStandardError,
			},
			output: nil,
			err:    ratifyerrors.ErrorCodeRepositoryOperationFailure.WithDetail(""),
		},
		{
			name: "resolve error forbidden error code",
			subjectRef: common.Reference{
				Original: "localhost:5000/net-monitor:v1",
				Path:     "localhost:5000/net-monitor",
				Tag:      "v1",
				Digest:   testSubjectDigest,
			},
			repository: mocks.TestRepository{
				ResolveErr: forbiddenError,
			},
			output: nil,
			err:    ratifyerrors.ErrorCodeRepositoryOperationFailure.WithDetail(""),
		},
		{
			name: "resolve error unauthorized error code",
			subjectRef: common.Reference{
				Original: "localhost:5000/net-monitor:v1",
				Path:     "localhost:5000/net-monitor",
				Tag:      "v1",
				Digest:   testSubjectDigest,
			},
			repository: mocks.TestRepository{
				ResolveErr: unauthorizedError,
			},
			output: nil,
			err:    ratifyerrors.ErrorCodeRepositoryOperationFailure.WithDetail(""),
		},
	}
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			refs, err := getCosignReferences(ctx, testcase.subjectRef, testcase.repository)
			if !errors.Is(err, testcase.err) {
				t.Fatalf("test case: %s; expected error to be %v, but got %v", testcase.name, testcase.err, err)
			}
			if !reflect.DeepEqual(refs, testcase.output) {
				t.Fatalf("test case: %s; expected reference descriptors to be %v, but got %v", testcase.name, testcase.output, refs)
			}
		})
	}
}
