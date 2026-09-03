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

	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore/config"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

type MemoryTestStore struct {
	Subjects  map[digest.Digest]*ocispecs.SubjectDescriptor
	Referrers map[digest.Digest][]ocispecs.ReferenceDescriptor
	Manifests map[digest.Digest]ocispecs.ReferenceManifest
	Blobs     map[digest.Digest][]byte
}

func (store *MemoryTestStore) ListReferrers(_ context.Context, _ common.Reference, _ []string, _ string, subjectDesc *ocispecs.SubjectDescriptor) (referrerstore.ListReferrersResult, error) {
	// assume subjectDesc is given and good

	if item, ok := store.Referrers[subjectDesc.Digest]; ok {
		return referrerstore.ListReferrersResult{
			Referrers: item,
			NextToken: "",
		}, nil
	}

	return referrerstore.ListReferrersResult{}, nil
}

func (store *MemoryTestStore) Name() string {
	return "memoryTestStore"
}

func (store *MemoryTestStore) GetBlobContent(_ context.Context, _ common.Reference, digest digest.Digest) ([]byte, error) {
	if item, ok := store.Blobs[digest]; ok {
		return item, nil
	}
	return nil, fmt.Errorf("blob not found")
}

func (store *MemoryTestStore) GetReferenceManifest(_ context.Context, _ common.Reference, desc ocispecs.ReferenceDescriptor) (ocispecs.ReferenceManifest, error) {
	if item, ok := store.Manifests[desc.Digest]; ok {
		return item, nil
	}
	return ocispecs.ReferenceManifest{}, fmt.Errorf("manifest not found")
}

func (store *MemoryTestStore) GetConfig() *config.StoreConfig {
	return &config.StoreConfig{}
}

func (store *MemoryTestStore) GetSubjectDescriptor(_ context.Context, subjectReference common.Reference) (*ocispecs.SubjectDescriptor, error) {
	if item, ok := store.Subjects[subjectReference.Digest]; ok {
		return item, nil
	}

	return nil, fmt.Errorf("subject not found for %s", subjectReference.Digest)
}

func createEmptyMemoryTestStore() *MemoryTestStore {
	return &MemoryTestStore{Subjects: make(map[digest.Digest]*ocispecs.SubjectDescriptor), Referrers: make(map[digest.Digest][]ocispecs.ReferenceDescriptor)}
}

func CreateNewTestStoreForNestedSbom() referrerstore.ReferrerStore {
	store := createEmptyMemoryTestStore()

	addSignedImageWithSignedSbomToStore(store)

	return store
}

const (
	TestSubjectWithDigest = "localhost:5000/net-monitor:v1@sha256:b556844e6e59451caf4429eb1de50aa7c50e4b1cc985f9f5893affe4b73f9935"
	SbomArtifactType      = "application/spdx+json"
	SignatureArtifactType = "application/vnd.cncf.notary.signature"
	dockerMediaType       = "application/vnd.docker.distribution.manifest.v2+json"
	artifactMediaType     = "application/vnd.oci.artifact.manifest.v1+json"
)

func addSignedImageWithSignedSbomToStore(store *MemoryTestStore) {
	imageDigest := digest.NewDigestFromEncoded("sha256", "b556844e6e59451caf4429eb1de50aa7c50e4b1cc985f9f5893affe4b73f9935")
	sbomDigest := digest.NewDigestFromEncoded("sha256", "9393779549fca5758811d7cf0444ddb1b254cb24b44fe1cf80fac6fd3199817f")
	sbomSignatureDigest := digest.NewDigestFromEncoded("sha256", "ace31a6d260ee372caaed757b3411b634b2cecc379c31fda979dba4470699227")
	imageSignatureDigest := digest.NewDigestFromEncoded("sha256", "1e42660cb1eec8d21b66c459796717da47e1b540542d6ef26c9f28ad74da9fa5")

	// Add image subject
	store.Subjects[imageDigest] = &ocispecs.SubjectDescriptor{
		Descriptor: v1.Descriptor{
			Digest:    imageDigest,
			MediaType: dockerMediaType,
		},
	}

	// Add image refeerrers
	store.Referrers[imageDigest] = []ocispecs.ReferenceDescriptor{
		{
			Descriptor: v1.Descriptor{
				MediaType: artifactMediaType,
				Digest:    sbomDigest,
			},
			ArtifactType: SbomArtifactType,
		},
		{
			Descriptor: v1.Descriptor{
				MediaType: artifactMediaType,
				Digest:    imageSignatureDigest,
			},
			ArtifactType: SignatureArtifactType,
		},
	}

	// Add sbom subject
	store.Subjects[sbomDigest] = &ocispecs.SubjectDescriptor{
		Descriptor: v1.Descriptor{
			Digest:    sbomDigest,
			MediaType: artifactMediaType,
		},
	}

	// Add sbom refeerrers
	store.Referrers[sbomDigest] = []ocispecs.ReferenceDescriptor{
		{
			Descriptor: v1.Descriptor{
				MediaType: artifactMediaType,
				Digest:    sbomSignatureDigest,
			},
			ArtifactType: SignatureArtifactType,
		},
	}
}
