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
	"fmt"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/ratify-project/ratify/pkg/common"
	"github.com/ratify-project/ratify/pkg/ocispecs"
	"github.com/ratify-project/ratify/pkg/referrerstore/mocks"
	"github.com/ratify-project/ratify/pkg/verifier/plugin/skel"
)

const testVersion = "1.0.0"

func TestParseInput(t *testing.T) {
	tests := []struct {
		name        string
		stdin       []byte
		wantName    string
		wantType    string
		wantErr     bool
		errContains string
	}{
		{
			name:     "valid input with all fields",
			stdin:    []byte(`{"config":{"name":"slsa","type":"slsa","expectedVerifiedLevels":["SLSA_SOURCE_LEVEL_2"],"expectedVerifierId":"test-verifier","expectedResourceUri":"test-resource"}}`),
			wantName: "slsa",
			wantType: "slsa",
			wantErr:  false,
		},
		{
			name:     "valid input with empty config",
			stdin:    []byte(`{"config":{}}`),
			wantName: "",
			wantType: "",
			wantErr:  false,
		},
		{
			name:        "invalid JSON",
			stdin:       []byte(`not-json`),
			wantErr:     true,
			errContains: "failed to parse stdin",
		},
		{
			name:        "empty input",
			stdin:       []byte(``),
			wantErr:     true,
			errContains: "failed to parse stdin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := parseInput(tt.stdin)
			if tt.wantErr {
				if err == nil {
					t.Fatal("parseInput() expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Fatalf("parseInput() error = %v, want containing %q", err, tt.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseInput() unexpected error: %v", err)
			}
			if config.Name != tt.wantName {
				t.Fatalf("parseInput() name = %q, want %q", config.Name, tt.wantName)
			}
			if config.Type != tt.wantType {
				t.Fatalf("parseInput() type = %q, want %q", config.Type, tt.wantType)
			}
			if tt.wantName == "slsa" {
				// Assert the full-config fields are parsed correctly
				if config.ExpectedVerifierID != "test-verifier" {
					t.Fatalf("parseInput() expectedVerifierId = %q, want %q", config.ExpectedVerifierID, "test-verifier")
				}
				if config.ExpectedResourceURI != "test-resource" {
					t.Fatalf("parseInput() expectedResourceUri = %q, want %q", config.ExpectedResourceURI, "test-resource")
				}
				if len(config.ExpectedVerifiedLevels) != 1 || config.ExpectedVerifiedLevels[0] != "SLSA_SOURCE_LEVEL_2" {
					t.Fatalf("parseInput() expectedVerifiedLevels = %v, want [SLSA_SOURCE_LEVEL_2]", config.ExpectedVerifiedLevels)
				}
			}
		})
	}
}

func TestVerifyReference(t *testing.T) {
	manifestDigest := digest.FromString("test_manifest_digest")
	manifestDigest2 := digest.FromString("test_manifest_digest_2")
	blobDigest := digest.FromString("test_blob_digest")
	blobDigest2 := digest.FromString("test_blob_digest_2")

	tests := []struct {
		name      string
		stdinData string
		manifest  ocispecs.ReferenceManifest
		blobs     map[digest.Digest][]byte
		refDesc   ocispecs.ReferenceDescriptor
		wantErr   bool
		wantMsg   string
		wantOK    *bool // nil means check error only
	}{
		{
			name:      "invalid stdin data",
			stdinData: "",
			wantErr:   true,
		},
		{
			name:      "failed to get reference manifest",
			stdinData: `{"config":{"name":"slsa","type":"slsa"}}`,
			manifest:  ocispecs.ReferenceManifest{},
			refDesc: ocispecs.ReferenceDescriptor{
				Descriptor: oci.Descriptor{
					Digest: manifestDigest2,
				},
			},
			wantErr: true,
		},
		{
			name:      "empty blobs",
			stdinData: `{"config":{"name":"slsa","type":"slsa"}}`,
			manifest:  ocispecs.ReferenceManifest{},
			refDesc: ocispecs.ReferenceDescriptor{
				Descriptor: oci.Descriptor{
					Digest: manifestDigest,
				},
			},
			wantOK:  boolPtr(false),
			wantMsg: "no blobs found",
		},
		{
			name:      "blob exceeds max size",
			stdinData: `{"config":{"name":"slsa","type":"slsa"}}`,
			manifest: ocispecs.ReferenceManifest{
				Blobs: []oci.Descriptor{
					{
						Digest: blobDigest,
						Size:   maxBlobSize + 1, // exceeds 50MB limit
					},
				},
			},
			blobs: map[digest.Digest][]byte{blobDigest: []byte("data")},
			refDesc: ocispecs.ReferenceDescriptor{
				Descriptor: oci.Descriptor{
					Digest: manifestDigest,
				},
			},
			// large blob is skipped, loop ends, returns success
			wantOK: boolPtr(true),
		},
		{
			name:      "failed to get blob content",
			stdinData: `{"config":{"name":"slsa","type":"slsa"}}`,
			manifest: ocispecs.ReferenceManifest{
				Blobs: []oci.Descriptor{
					{
						Digest: blobDigest2, // not in store
						Size:   100,
					},
				},
			},
			blobs: map[digest.Digest][]byte{},
			refDesc: ocispecs.ReferenceDescriptor{
				Descriptor: oci.Descriptor{
					Digest: manifestDigest,
				},
			},
			wantErr: true,
		},
		{
			name:      "verifier type falls back to name when type is empty",
			stdinData: `{"config":{"name":"my-slsa","type":""}}`,
			manifest:  ocispecs.ReferenceManifest{},
			refDesc: ocispecs.ReferenceDescriptor{
				Descriptor: oci.Descriptor{
					Digest: manifestDigest,
				},
			},
			wantOK:  boolPtr(false),
			wantMsg: "no blobs found",
		},
		{
			name:      "blob with invalid attestation returns failure",
			stdinData: `{"config":{"name":"slsa","type":"slsa"}}`,
			manifest: ocispecs.ReferenceManifest{
				Blobs: []oci.Descriptor{
					{
						Digest: blobDigest,
						Size:   100,
					},
				},
			},
			blobs: map[digest.Digest][]byte{blobDigest: []byte("not-a-valid-attestation")},
			refDesc: ocispecs.ReferenceDescriptor{
				Descriptor: oci.Descriptor{
					Digest: manifestDigest,
				},
			},
			wantOK:  boolPtr(false),
			wantMsg: "can not get VSA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmdArgs := &skel.CmdArgs{
				Version:   testVersion,
				Subject:   "test_subject",
				StdinData: []byte(tt.stdinData),
			}
			blobs := tt.blobs
			if blobs == nil {
				blobs = map[digest.Digest][]byte{}
			}
			testStore := &mocks.MemoryTestStore{
				Manifests: map[digest.Digest]ocispecs.ReferenceManifest{manifestDigest: tt.manifest},
				Blobs:     blobs,
			}
			subjectRef := common.Reference{
				Path:     "test_subject_path",
				Original: "test_subject",
			}

			result, err := VerifyReference(cmdArgs, subjectRef, tt.refDesc, testStore)

			if tt.wantErr {
				if err == nil {
					t.Fatal("VerifyReference() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("VerifyReference() unexpected error: %v", err)
			}

			if result == nil {
				t.Fatal("VerifyReference() result is nil")
			}

			if tt.wantOK != nil && result.IsSuccess != *tt.wantOK {
				t.Fatalf("VerifyReference() IsSuccess = %v, want %v", result.IsSuccess, *tt.wantOK)
			}

			if tt.wantMsg != "" && !strings.Contains(result.Message, tt.wantMsg) {
				t.Fatalf("VerifyReference() Message = %q, want containing %q", result.Message, tt.wantMsg)
			}

			// Assert verifier type fallback: when Type is empty, Name should be used as Type
			if tt.name == "verifier type falls back to name when type is empty" {
				if result.Type != "my-slsa" {
					t.Fatalf("VerifyReference() Type = %q, want %q (should fall back to name)", result.Type, "my-slsa")
				}
			}
		})
	}
}

func TestVerifyReferenceMaxBlobs(t *testing.T) {
	manifestDigest := digest.FromString("test_manifest")
	blobs := make(map[digest.Digest][]byte)
	blobDescs := make([]oci.Descriptor, 0, maxBlobs+5)

	// Create more than maxBlobs blobs
	for i := 0; i < maxBlobs+5; i++ {
		d := digest.FromString(fmt.Sprintf("blob_%d", i))
		blobs[d] = []byte("not-a-valid-attestation")
		blobDescs = append(blobDescs, oci.Descriptor{
			Digest: d,
			Size:   100,
		})
	}

	cmdArgs := &skel.CmdArgs{
		Version:   testVersion,
		Subject:   "test_subject",
		StdinData: []byte(`{"config":{"name":"slsa","type":"slsa"}}`),
	}
	testStore := &mocks.MemoryTestStore{
		Manifests: map[digest.Digest]ocispecs.ReferenceManifest{
			manifestDigest: {Blobs: blobDescs},
		},
		Blobs: blobs,
	}
	subjectRef := common.Reference{
		Path:     "test_subject_path",
		Original: "test_subject",
	}
	refDesc := ocispecs.ReferenceDescriptor{
		Descriptor: oci.Descriptor{
			Digest: manifestDigest,
		},
	}

	// All blobs have invalid attestation data, so GetVsa will fail on the first blob
	// and return a non-success result. The key behavior: it should not process more
	// than maxBlobs blobs and should not crash.
	result, err := VerifyReference(cmdArgs, subjectRef, refDesc, testStore)
	if err != nil {
		t.Fatalf("VerifyReference() unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("VerifyReference() result is nil")
	}
	if result.IsSuccess {
		t.Fatal("VerifyReference() IsSuccess = true, want false (invalid attestation data)")
	}
	if !strings.Contains(result.Message, "can not get VSA") {
		t.Fatalf("VerifyReference() Message = %q, want containing 'can not get VSA'", result.Message)
	}
}

func boolPtr(b bool) *bool {
	return &b
}
