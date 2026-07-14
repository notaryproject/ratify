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
	"fmt"
	"time"

	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore/config"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

type TestStore struct {
	References   []ocispecs.ReferenceDescriptor
	ResolveMap   map[string]digest.Digest
	ExtraSubject string
}

func (s *TestStore) Name() string {
	return "testStore"
}

func (s *TestStore) ListReferrers(_ context.Context, _ common.Reference, _ []string, _ string, _ *ocispecs.SubjectDescriptor) (referrerstore.ListReferrersResult, error) {
	return referrerstore.ListReferrersResult{Referrers: s.References}, nil
}

func (s *TestStore) GetBlobContent(_ context.Context, _ common.Reference, _ digest.Digest) ([]byte, error) {
	return nil, nil
}

func (s *TestStore) GetReferenceManifest(_ context.Context, _ common.Reference, _ ocispecs.ReferenceDescriptor) (ocispecs.ReferenceManifest, error) {
	return ocispecs.ReferenceManifest{}, nil
}

func (s *TestStore) GetConfig() *config.StoreConfig {
	return &config.StoreConfig{}
}

func (s *TestStore) GetSubjectDescriptor(_ context.Context, subjectReference common.Reference) (*ocispecs.SubjectDescriptor, error) {
	if s.ExtraSubject != "" && subjectReference.Original == s.ExtraSubject {
		time.Sleep(2 * time.Second)
	}

	if s.ResolveMap != nil {
		if result, ok := s.ResolveMap[subjectReference.Tag]; ok {
			return &ocispecs.SubjectDescriptor{Descriptor: v1.Descriptor{Digest: result}}, nil
		}
	}

	return nil, fmt.Errorf("cannot resolve digest for the subject reference")
}
