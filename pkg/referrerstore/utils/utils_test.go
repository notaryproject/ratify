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

package utils

import (
	"context"
	"testing"

	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore/mocks"
	"github.com/notaryproject/ratify/v2/pkg/utils"
	"github.com/opencontainers/go-digest"
)

func TestResolveSubjectDescriptor_Success(t *testing.T) {
	testDigest := digest.FromString("test")
	store1 := &mocks.TestStore{}
	store2 := &mocks.TestStore{
		ResolveMap: map[string]digest.Digest{
			"v1": testDigest,
		},
	}
	subjectReference, err := utils.ParseSubjectReference("localhost:5000/net-monitor:v1")
	if err != nil {
		t.Fatalf("failed to parse the subject %v", err)
	}

	result, err := ResolveSubjectDescriptor(context.Background(), &[]referrerstore.ReferrerStore{store1, store2}, subjectReference)

	if err != nil {
		t.Fatalf("failed to get the subject descriptor %v", err)
	}

	if result.Digest != testDigest {
		t.Fatalf("digest mismatch expected %v actual %v", testDigest, result.Digest)
	}
}

func TestResolveSubjectDescriptor_Failure(t *testing.T) {
	store1 := &mocks.TestStore{}
	store2 := &mocks.TestStore{}
	subjectReference, err := utils.ParseSubjectReference("localhost:5000/net-monitor:v1")
	if err != nil {
		t.Fatalf("failed to parse the subject %v", err)
	}

	_, err = ResolveSubjectDescriptor(context.Background(), &[]referrerstore.ReferrerStore{store1, store2}, subjectReference)

	if err == nil {
		t.Fatalf("expected resolve to fail but didnot get any error")
	}
}
