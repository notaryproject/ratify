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
	"reflect"
	"testing"

	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
)

const TestArtifactType = "application/vnd.test.artifacttype"

func TestOciManifestToReferenceManifest(t *testing.T) {
	type args struct {
		ociManifest oci.Manifest
	}
	tests := []struct {
		name string
		args args
		want ocispecs.ReferenceManifest
	}{
		{
			name: "empty",
			args: args{
				ociManifest: oci.Manifest{},
			},
			want: ocispecs.ReferenceManifest{
				MediaType:    "",
				ArtifactType: "",
			},
		},
		{
			name: "simple",
			args: args{
				ociManifest: oci.Manifest{
					MediaType: "application/vnd.oci.image.manifest.v1+json",
					Config: oci.Descriptor{
						MediaType: TestArtifactType,
					},
				},
			},
			want: ocispecs.ReferenceManifest{
				MediaType:    "application/vnd.oci.image.manifest.v1+json",
				ArtifactType: TestArtifactType,
			},
		},
		{
			name: "empty config media type",
			args: args{
				ociManifest: oci.Manifest{
					MediaType: "application/vnd.oci.image.manifest.v1+json",
					Config: oci.Descriptor{
						MediaType: oci.DescriptorEmptyJSON.MediaType,
					},
					ArtifactType: TestArtifactType,
				},
			},
			want: ocispecs.ReferenceManifest{
				MediaType:    "application/vnd.oci.image.manifest.v1+json",
				ArtifactType: TestArtifactType,
			},
		},
		{
			name: "layers",
			args: args{
				ociManifest: oci.Manifest{
					MediaType: "application/vnd.oci.image.manifest.v1+json",
					Config: oci.Descriptor{
						MediaType: TestArtifactType,
					},
					Layers: []oci.Descriptor{
						{
							MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
						},
					},
				},
			},
			want: ocispecs.ReferenceManifest{
				MediaType:    "application/vnd.oci.image.manifest.v1+json",
				ArtifactType: TestArtifactType,
				Blobs: []oci.Descriptor{
					{
						MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := OciManifestToReferenceManifest(tt.args.ociManifest); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("OciManifestToReferenceManifest() = %v, want %v", got, tt.want)
			}
		})
	}
}
