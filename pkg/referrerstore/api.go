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

package referrerstore

import (
	"context"

	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore/config"
	"github.com/opencontainers/go-digest"
)

// ListReferrersResult represents the result of ListReferrers API
type ListReferrersResult struct {
	Referrers []ocispecs.ReferenceDescriptor
	NextToken string
}

// ReferrerStore is an interface that defines methods to query the graph of supply chain content including its related content
type ReferrerStore interface {
	// Name is the name of the store
	Name() string

	// ListReferrers returns the immediate set of supply chain objects for the given subject
	// represented as artifact manifests
	ListReferrers(ctx context.Context, subjectReference common.Reference, artifactTypes []string, nextToken string, subjectDesc *ocispecs.SubjectDescriptor) (ListReferrersResult, error)

	// GetBlobContent returns the blob with the given digest
	// WARNING: This API is intended to use for small objects like signatures, SBoMs
	GetBlobContent(ctx context.Context, subjectReference common.Reference, digest digest.Digest) ([]byte, error)

	// GetReferenceManifest returns the reference artifact manifest as given by the descriptor
	GetReferenceManifest(ctx context.Context, subjectReference common.Reference, referenceDesc ocispecs.ReferenceDescriptor) (ocispecs.ReferenceManifest, error)

	// GetConfig returns the configuration of this store
	GetConfig() *config.StoreConfig

	// GetSubjectDescriptor returns the descriptor for the given subject.
	GetSubjectDescriptor(ctx context.Context, subjectReference common.Reference) (*ocispecs.SubjectDescriptor, error)
}
