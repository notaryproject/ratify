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

package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore/mocks"
	"github.com/notaryproject/ratify/v2/pkg/verifier/plugin/skel"
	"github.com/opencontainers/go-digest"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
)

const mediaType string = "application/schema+json"

func TestVerifyReference(t *testing.T) {
	manifestDigest := digest.FromString("test_manifest_digest")
	manifestDigest2 := digest.FromString("test_manifest_digest_2")
	blobDigest := digest.FromString("test_blob_digest")
	blobDigest2 := digest.FromString("test_blob_digest_2")
	type args struct {
		stdinData         string
		referenceManifest ocispecs.ReferenceManifest
		blobContent       string
		refDesc           ocispecs.ReferenceDescriptor
	}
	type want struct {
		message     string
		errorReason string
		err         error
	}
	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "invalid stdin data",
			args: args{},
			want: want{
				err: errors.New("failed to parse stdin for the input: unexpected end of JSON input"),
			},
		},
		{
			name: "failed to get reference manifest",
			args: args{
				stdinData:         `{"config":{"name":"schemavalidator","type":"schemavalidator"}}`,
				referenceManifest: ocispecs.ReferenceManifest{},
				refDesc: ocispecs.ReferenceDescriptor{
					Descriptor: oci.Descriptor{
						Digest: manifestDigest2,
					},
					ArtifactType: mediaType,
				},
			},
			want: want{
				err: errors.New("error fetching reference manifest for subject: test_subject reference descriptor: { sha256:b55e209647d87fcd95a94c59ff4d342e42bf10f02a7c10b5192131f8d959ff5a 0 [] map[] [] <nil> }"),
			},
		},
		{
			name: "empty blobs",
			args: args{
				stdinData:         `{"config":{"name":"schemavalidator","type":"schemavalidator"}}`,
				referenceManifest: ocispecs.ReferenceManifest{},
				refDesc: ocispecs.ReferenceDescriptor{
					Descriptor: oci.Descriptor{
						Digest: manifestDigest,
					},
					ArtifactType: mediaType,
				},
			},
			want: want{
				errorReason: fmt.Sprintf("No blobs found for referrer %s@%s.", "test_subject_path", manifestDigest.String()),
			},
		},
		{
			name: "get blob content error",
			args: args{
				stdinData: `{"config":{"name":"schemavalidator","type":"schemavalidator"}}`,
				referenceManifest: ocispecs.ReferenceManifest{
					Blobs: []oci.Descriptor{
						{
							MediaType: mediaType,
							Digest:    blobDigest2,
						},
					},
				},
				refDesc: ocispecs.ReferenceDescriptor{
					Descriptor: oci.Descriptor{
						Digest: manifestDigest,
					},
					ArtifactType: mediaType,
				},
			},
			want: want{
				err: fmt.Errorf("error fetching blob for subject:[%s] digest:[%s]", "test_subject", blobDigest2.String()),
			},
		},
		{
			name: "process mediaType error",
			args: args{
				stdinData: `{"config":{"name":"schemavalidator","type":"schemavalidator"}}`,
				referenceManifest: ocispecs.ReferenceManifest{
					Blobs: []oci.Descriptor{
						{
							MediaType: mediaType,
							Digest:    blobDigest,
						},
					},
				},
				refDesc: ocispecs.ReferenceDescriptor{
					Descriptor: oci.Descriptor{
						Digest: manifestDigest,
					},
					ArtifactType: mediaType,
				},
			},
			want: want{
				message:     fmt.Sprintf("schema validation failed for digest:[%s], media type:[%s].", blobDigest.String(), mediaType),
				errorReason: "media type not configured for plugin:[application/schema+json]",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmdArgs := &skel.CmdArgs{
				Version:   "1.0.0",
				Subject:   "test_subject",
				StdinData: []byte(tt.args.stdinData),
			}
			testStore := &mocks.MemoryTestStore{
				Manifests: map[digest.Digest]ocispecs.ReferenceManifest{manifestDigest: tt.args.referenceManifest},
				Blobs:     map[digest.Digest][]byte{blobDigest: []byte(tt.args.blobContent)},
			}
			subjectRef := common.Reference{
				Path:     "test_subject_path",
				Original: "test_subject",
			}
			verifierResult, err := VerifyReference(cmdArgs, subjectRef, tt.args.refDesc, testStore)
			if err != nil && err.Error() != tt.want.err.Error() {
				t.Fatalf("verifyReference() error = %v, wantErr %v", err, tt.want.err)
			}
			if verifierResult != nil {
				if verifierResult.Message != tt.want.message {
					t.Fatalf("verifyReference() verifier report message = %s, want = %s", verifierResult.Message, tt.want.message)
				}
				if verifierResult.ErrorReason != tt.want.errorReason {
					t.Fatalf("verifyReference() verifier report error reason = %s, want = %s", verifierResult.ErrorReason, tt.want.errorReason)
				}
			}
		})
	}
}
