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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore/mocks"
	"github.com/notaryproject/ratify/v2/pkg/verifier/plugin/skel"
	"github.com/notaryproject/ratify/v2/plugins/verifier/sbom/utils"
	"github.com/opencontainers/go-digest"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
)

const mediaType string = "application/vnd.syft+json"

func TestProcessSPDXJsonMediaType(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "bom.json"))
	if err != nil {
		t.Fatalf("error reading %s", filepath.Join("testdata", "bom.json"))
	}
	vr := processSpdxJSONMediaType("test", "", b, nil, nil)
	if !vr.IsSuccess {
		t.Fatalf("expected to successfully verify schema")
	}
}

func TestProcessInvalidSPDXJsonMediaType(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "invalid-bom.json"))
	if err != nil {
		t.Fatalf("error reading %s", filepath.Join("testdata", "invalid-bom.json"))
	}
	report := processSpdxJSONMediaType("test", "", b, nil, nil)

	if !strings.Contains(report.Message, "failed to verify artifact") {
		t.Fatalf("report message: %s does not contain expected error message", report.Message)
	}
	if report.ErrorReason != "JSON document does not contain spdxVersion field" {
		t.Fatalf("expected error reason: %s, got: %s", "JSON document does not contain spdxVersion field", report.ErrorReason)
	}
}

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
				stdinData:         `{"config":{"name":"sbom","type":"sbom"}}`,
				referenceManifest: ocispecs.ReferenceManifest{},
				refDesc: ocispecs.ReferenceDescriptor{
					Descriptor: oci.Descriptor{
						Digest: manifestDigest2,
					},
					ArtifactType: mediaType,
				},
			},
			want: want{
				message:     "Failed to fetch reference manifest for subject: test_subject reference descriptor: { sha256:b55e209647d87fcd95a94c59ff4d342e42bf10f02a7c10b5192131f8d959ff5a 0 [] map[] [] <nil> }",
				errorReason: "manifest not found",
			},
		},
		{
			name: "empty blobs",
			args: args{
				stdinData:         `{"config":{"name":"sbom","type":"sbom"}}`,
				referenceManifest: ocispecs.ReferenceManifest{},
				refDesc: ocispecs.ReferenceDescriptor{
					Descriptor: oci.Descriptor{
						Digest: manifestDigest,
					},
					ArtifactType: mediaType,
				},
			},
			want: want{
				message:     "SBOM validation failed",
				errorReason: fmt.Sprintf("No layers found in manifest for referrer %s@%s", "test_subject_path", manifestDigest.String()),
			},
		},
		{
			name: "get blob content error",
			args: args{
				stdinData: `{"config":{"name":"sbom","type":"sbom"}}`,
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
				message:     fmt.Sprintf("Failed to fetch blob for subject: test_subject digest: %s", blobDigest2.String()),
				errorReason: "blob not found",
			},
		},
		{
			name: "unsupported artifactType",
			args: args{
				stdinData: `{"config":{"name":"sbom","type":"sbom"}}`,
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
				message:     "Failed to process SBOM blobs.",
				errorReason: "Unsupported artifactType: application/vnd.syft+json",
			},
		},
		{
			name: "process spdx json mediaType error",
			args: args{
				stdinData: `{"config":{"name":"sbom","type":"sbom"}}`,
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
					ArtifactType: SpdxJSONMediaType,
				},
			},
			want: want{
				message:     "failed to verify artifact: sbom",
				errorReason: "unexpected end of JSON input",
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

func TestGetViolations(t *testing.T) {
	disallowedPackage := utils.PackageInfo{
		Name:    "libcrypto3",
		Version: "3.0.7-r2",
	}

	disallowedPackageNoName := utils.PackageInfo{
		Name:    "",
		Version: "3.0.7-r2",
	}

	disallowedPackageNoVersion := utils.PackageInfo{
		Name: "libcrypto3",
	}

	packageViolation := utils.PackageLicense{
		Name:    "libcrypto3",
		Version: "3.0.7-r2",
		License: "Apache-2.0",
	}

	licenseViolation := utils.PackageLicense{
		Name:    "libc-utils",
		Version: "0.7.2-r3",
		License: "BSD-2-Clause AND LicenseRef-AND AND BSD-3-Clause",
	}

	violation2 := utils.PackageLicense{
		Name:    "zlib",
		License: "Zlib",
		Version: "1.2.13-r0",
	}

	disallowedPackage2 := utils.PackageInfo{
		Name:    "libcrypto3",
		Version: "3.0.7-r3",
	}

	b, err := os.ReadFile(filepath.Join("testdata", "syftbom.spdx.json"))
	if err != nil {
		t.Fatalf("error reading %s", filepath.Join("testdata", "syftbom.spdx.json"))
	}

	cases := []struct {
		description               string
		disallowedLicenses        []string
		disallowedPackages        []utils.PackageInfo
		expectedLicenseViolations []utils.PackageLicense
		expectedPackageViolations []utils.PackageLicense
		enabled                   bool
	}{
		{
			description:               "disallowed packages with no version",
			disallowedLicenses:        []string{"MPL"},
			expectedLicenseViolations: nil,
			expectedPackageViolations: nil,
		},
		{
			description:               "disallowed packages with no version",
			disallowedPackages:        []utils.PackageInfo{disallowedPackageNoVersion},
			expectedLicenseViolations: []utils.PackageLicense{},
			expectedPackageViolations: []utils.PackageLicense{packageViolation},
		},
		{
			description:               "package and license violation found",
			disallowedLicenses:        []string{"BSD-3-Clause", "Zlib"},
			disallowedPackages:        []utils.PackageInfo{disallowedPackage},
			expectedLicenseViolations: []utils.PackageLicense{licenseViolation, violation2},
			expectedPackageViolations: []utils.PackageLicense{packageViolation},
		},
		{
			description:               "invalid disallow package",
			disallowedPackages:        []utils.PackageInfo{disallowedPackageNoName},
			expectedLicenseViolations: []utils.PackageLicense{},
			expectedPackageViolations: []utils.PackageLicense{},
		},
		{
			description:               "license violation found",
			disallowedLicenses:        []string{"Zlib"},
			disallowedPackages:        []utils.PackageInfo{},
			expectedLicenseViolations: []utils.PackageLicense{violation2},
			expectedPackageViolations: []utils.PackageLicense{},
		},
		{
			description:               "license violation case insensitive",
			disallowedLicenses:        []string{"zlib"},
			disallowedPackages:        []utils.PackageInfo{},
			expectedLicenseViolations: []utils.PackageLicense{violation2},
			expectedPackageViolations: []utils.PackageLicense{},
		},
		{
			description:               "package violation not found",
			disallowedLicenses:        []string{},
			disallowedPackages:        []utils.PackageInfo{disallowedPackage2},
			expectedLicenseViolations: []utils.PackageLicense{},
			expectedPackageViolations: []utils.PackageLicense{},
			enabled:                   true,
		},
		{
			description:               "license violation not found",
			disallowedLicenses:        []string{"GPL-3.0-only"},
			disallowedPackages:        []utils.PackageInfo{},
			expectedLicenseViolations: []utils.PackageLicense{},
			expectedPackageViolations: []utils.PackageLicense{},
		},
	}

	for _, tc := range cases {
		t.Run("test scenario", func(t *testing.T) {
			report := processSpdxJSONMediaType("test", "", b, tc.disallowedLicenses, tc.disallowedPackages)

			if len(tc.expectedPackageViolations) != 0 || len(tc.expectedLicenseViolations) != 0 {
				if report.IsSuccess {
					t.Fatalf("Test %s failed. Expected IsSuccess: true, got: false", tc.description)
				}
			}

			if len(tc.expectedPackageViolations) == 0 && len(tc.expectedLicenseViolations) == 0 {
				if !report.IsSuccess {
					t.Fatalf("Test %s failed. Expected IsSuccess: false, got: true", tc.description)
				}
			}

			if len(tc.expectedPackageViolations) != 0 {
				extensionData := report.Extensions.(map[string]interface{})
				packageViolation := extensionData[PackageViolation].([]utils.PackageLicense)
				AssertEquals(tc.expectedPackageViolations, packageViolation, tc.description, t)
			}

			if len(tc.expectedLicenseViolations) != 0 {
				extensionData := report.Extensions.(map[string]interface{})
				licensesViolation := extensionData[LicenseViolation].([]utils.PackageLicense)
				AssertEquals(tc.expectedLicenseViolations, licensesViolation, tc.description, t)
			}
		})
	}
}

func AssertEquals(expected []utils.PackageLicense, actual []utils.PackageLicense, description string, t *testing.T) {
	if len(expected) != len(actual) {
		t.Fatalf("Test %s failed. Expected len of expectedPackageViolations %v, got: %v", description, len(expected), len(actual))
	}

	for i, packageInfo := range expected {
		if packageInfo.Name != actual[i].Name {
			t.Fatalf("Test %s failed. Expected PackageName: %s, got: %s", description, packageInfo.Name, actual[i].Name)
		}
		if packageInfo.Version != actual[i].Version {
			t.Fatalf("Test %s Failed. expected PackageVersion: %s, got: %s", description, packageInfo.Version, actual[i].Version)
		}
		if packageInfo.License != actual[i].License {
			t.Fatalf("Test %s Failed. expected PackageLicense: %s, got: %s", description, packageInfo.License, actual[i].License)
		}
	}
}
