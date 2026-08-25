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
	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore/plugin/skel"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

func main() {
	skel.PluginMain("sample", "1.0.0", ListReferrers, GetBlobContent, GetReferenceManifest, GetSubjectDescriptor, []string{"1.0.0"})
}

func ListReferrers(_ *skel.CmdArgs, _ common.Reference, artifactTypes []string, _ string, _ *ocispecs.SubjectDescriptor) (*referrerstore.ListReferrersResult, error) {
	artifactType := ""
	if len(artifactTypes) > 0 {
		artifactType = artifactTypes[0]
	}
	return &referrerstore.ListReferrersResult{
		Referrers: []ocispecs.ReferenceDescriptor{{
			ArtifactType: artifactType,
		}},
		NextToken: "",
	}, nil
}

func GetBlobContent(_ *skel.CmdArgs, _ common.Reference, digest digest.Digest) ([]byte, error) {
	return []byte(digest.String()), nil
}

func GetSubjectDescriptor(_ *skel.CmdArgs, subjectReference common.Reference) (*ocispecs.SubjectDescriptor, error) {
	dig := subjectReference.Digest
	if dig == "" {
		dig = digest.FromString(subjectReference.Tag)
	}
	return &ocispecs.SubjectDescriptor{Descriptor: v1.Descriptor{Digest: dig}}, nil
}

func GetReferenceManifest(_ *skel.CmdArgs, _ common.Reference, _ digest.Digest) (ocispecs.ReferenceManifest, error) {
	return ocispecs.ReferenceManifest{MediaType: "testMediaType", ArtifactType: "testArtifactType"}, nil
}
