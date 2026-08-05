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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
	"github.com/notaryproject/ratify/v2/plugins/verifier/sbom/utils"

	// This import is required to utilize the oras built-in referrer store
	re "github.com/notaryproject/ratify/v2/errors"
	_ "github.com/notaryproject/ratify/v2/pkg/referrerstore/oras"
	"github.com/notaryproject/ratify/v2/pkg/verifier"
	"github.com/notaryproject/ratify/v2/pkg/verifier/plugin/skel"
	jsonLoader "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

// PluginConfig describes the configuration of the sbom verifier
type PluginConfig struct {
	Name               string              `json:"name"`
	Type               string              `json:"type"`
	DisallowedLicenses []string            `json:"disallowedLicenses,omitempty"`
	DisallowedPackages []utils.PackageInfo `json:"disallowedPackages,omitempty"`
}

type PluginInputConfig struct {
	Config PluginConfig `json:"config"`
}

const (
	SpdxJSONMediaType string = "application/spdx+json"
	CreationInfo      string = "creationInfo"
	LicenseViolation  string = "licenseViolations"
	PackageViolation  string = "packageViolations"
)

func main() {
	skel.PluginMain("sbom", "2.0.0-alpha.1", VerifyReference, []string{"1.0.0", "2.0.0-alpha.1"})
}

func parseInput(stdin []byte) (*PluginConfig, error) {
	conf := PluginInputConfig{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse stdin for the input: %w", err)
	}

	return &conf.Config, nil
}

func VerifyReference(args *skel.CmdArgs, subjectReference common.Reference, referenceDescriptor ocispecs.ReferenceDescriptor, referrerStore referrerstore.ReferrerStore) (*verifier.VerifierResult, error) {
	input, err := parseInput(args.StdinData)
	if err != nil {
		return nil, err
	}
	verifierType := input.Name
	if input.Type != "" {
		verifierType = input.Type
	}

	ctx := context.Background()
	referenceManifest, err := referrerStore.GetReferenceManifest(ctx, subjectReference, referenceDescriptor)
	if err != nil {
		storeErr := re.ErrorCodeGetReferenceManifestFailure.WithDetail(fmt.Sprintf("Failed to fetch reference manifest for subject: %s reference descriptor: %v", subjectReference, referenceDescriptor.Descriptor)).WithError(err)
		result := verifier.NewVerifierResult("", input.Name, verifierType, "", false, &storeErr, nil)
		return &result, nil
	}

	if len(referenceManifest.Blobs) == 0 {
		noBlobErr := re.ErrorCodeVerifyPluginFailure.WithDetail(fmt.Sprintf("No layers found in manifest for referrer %s@%s", subjectReference.Path, referenceDescriptor.Digest.String()))
		result := verifier.NewVerifierResult("", input.Name, verifierType, "SBOM validation failed", false, &noBlobErr, nil)
		return &result, nil
	}

	artifactType := referenceDescriptor.ArtifactType
	for _, blobDesc := range referenceManifest.Blobs {
		refBlob, err := referrerStore.GetBlobContent(ctx, subjectReference, blobDesc.Digest)

		if err != nil {
			storeErr := re.ErrorCodeGetBlobContentFailure.WithDetail(fmt.Sprintf("Failed to fetch blob for subject: %s digest: %s", subjectReference, blobDesc.Digest)).WithError(err)
			result := verifier.NewVerifierResult("", input.Name, verifierType, "", false, &storeErr, nil)
			return &result, nil
		}

		switch artifactType {
		case SpdxJSONMediaType:
			return processSpdxJSONMediaType(input.Name, verifierType, refBlob, input.DisallowedLicenses, input.DisallowedPackages), nil
		default:
			storeErr := re.ErrorCodeVerifyPluginFailure.WithDetail(fmt.Sprintf("Unsupported artifactType: %s", artifactType))
			result := verifier.NewVerifierResult("", input.Name, verifierType, "Failed to process SBOM blobs.", false, &storeErr, nil)
			return &result, nil
		}
	}
	result := verifier.NewVerifierResult("", input.Name, verifierType, "SBOM verification success. No license or package violation found.", true, nil, nil)
	return &result, nil
}

// getViolations returns the package and license violations based on the deny list
func getViolations(spdxDoc *spdx.Document, disallowedLicenses []string, disallowedPackages []utils.PackageInfo) ([]utils.PackageLicense, []utils.PackageLicense) {
	packageLicenses := utils.GetPackageLicenses(*spdxDoc)
	// load disallowed packageInfo into a map for easier existence check
	packageMap, packageNameMap := loadDisallowedPackagesMap(disallowedPackages)

	// detect violation
	licenseViolation, packageViolation := filterDisallowedPackages(packageLicenses, disallowedLicenses, packageMap, packageNameMap)
	return packageViolation, licenseViolation
}

// load disallowed packageInfo, and disallowed packageName into a map for easier existence check
func loadDisallowedPackagesMap(packages []utils.PackageInfo) (map[utils.PackageInfo]struct{}, map[string]struct{}) {
	packagesInfo := map[utils.PackageInfo]struct{}{}
	packagesName := map[string]struct{}{}

	for _, item := range packages {
		// if the deny list item has no specific version, add to separate map
		if len(item.Version) == 0 {
			packagesName[item.Name] = struct{}{}
		}
		packagesInfo[item] = struct{}{}
	}
	return packagesInfo, packagesName
}

// parse through the spdx blob and returns the verifier result
func processSpdxJSONMediaType(name string, verifierType string, refBlob []byte, disallowedLicenses []string, disallowedPackages []utils.PackageInfo) *verifier.VerifierResult {
	var err error
	var spdxDoc *v2_3.Document
	if spdxDoc, err = jsonLoader.Read(bytes.NewReader(refBlob)); spdxDoc != nil && err == nil {
		if len(disallowedLicenses) != 0 || len(disallowedPackages) != 0 {
			packageViolation, licenseViolation := getViolations(spdxDoc, disallowedLicenses, disallowedPackages)

			var extensionData = make(map[string]interface{})
			extensionData[CreationInfo] = spdxDoc.CreationInfo
			if len(licenseViolation) != 0 {
				extensionData[LicenseViolation] = licenseViolation
			}

			if len(packageViolation) != 0 {
				extensionData[PackageViolation] = packageViolation
			}

			if len(licenseViolation) != 0 || len(packageViolation) != 0 {
				sbomErr := re.ErrorCodeVerifyPluginFailure.WithDetail("License or package violation found.").WithRemediation("Please review extensions data for license and package violation found.")
				result := verifier.NewVerifierResult("", name, verifierType, "SBOM validation failed", false, &sbomErr, extensionData)
				return &result
			}
		}

		result := verifier.NewVerifierResult(
			"",
			name,
			verifierType,
			"SBOM verification success. No license or package violation found.",
			true,
			nil,
			map[string]interface{}{CreationInfo: spdxDoc.CreationInfo},
		)
		return &result
	}
	verifierErr := re.ErrorCodeVerifyPluginFailure.WithDetail(fmt.Sprintf("failed to verify artifact: %s", name)).WithError(err)
	result := verifier.NewVerifierResult("", name, verifierType, "", false, &verifierErr, nil)
	return &result
}

// iterate through all package info and check against the deny list
// return the violation packages
func filterDisallowedPackages(packageLicenses []utils.PackageLicense, disallowedLicense []string, disallowedPackage map[utils.PackageInfo]struct{}, disallowedPackageName map[string]struct{}) ([]utils.PackageLicense, []utils.PackageLicense) {
	var violationLicense []utils.PackageLicense
	var violationPackage []utils.PackageLicense

	for _, packageInfo := range packageLicenses {
		// if license contains disallowed, add to violation
		for _, disallowed := range disallowedLicense {
			if utils.ContainsLicense(strings.ToLower(packageInfo.License), strings.ToLower(disallowed)) {
				violationLicense = append(violationLicense, packageInfo)
			}
		}

		current := utils.PackageInfo{
			Name:    packageInfo.Name,
			Version: packageInfo.Version,
		}

		// check if this package is in the deny list by package name
		if _, ok := disallowedPackageName[current.Name]; ok {
			violationPackage = append(violationPackage, packageInfo)
		}

		//  check if this package is in the deny list by matching name and version
		if _, ok := disallowedPackage[current]; ok {
			violationPackage = append(violationPackage, packageInfo)
		}
	}
	return violationLicense, violationPackage
}
