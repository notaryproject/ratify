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
	"context"
	"encoding/json"
	"fmt"

	"github.com/notaryproject/ratify/v2/plugins/verifier/licensechecker/utils"

	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
	_ "github.com/notaryproject/ratify/v2/pkg/referrerstore/oras"
	"github.com/notaryproject/ratify/v2/pkg/verifier"
	"github.com/notaryproject/ratify/v2/pkg/verifier/plugin/skel"
)

type PluginConfig struct {
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	AllowedLicenses []string `json:"allowedLicenses"`
}

type PluginInputConfig struct {
	Config PluginConfig `json:"config"`
}

func main() {
	skel.PluginMain("licensechecker", "1.0.0", VerifyReference, []string{"1.0.0"})
}

func parseInput(stdin []byte) (*PluginConfig, error) {
	conf := PluginInputConfig{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse stdin for input: %w", err)
	}

	return &conf.Config, nil
}

func VerifyReference(args *skel.CmdArgs, subjectReference common.Reference, descriptor ocispecs.ReferenceDescriptor, store referrerstore.ReferrerStore) (*verifier.VerifierResult, error) {
	input, err := parseInput(args.StdinData)
	if err != nil {
		return nil, err
	}
	verifierType := input.Name
	if input.Type != "" {
		verifierType = input.Type
	}
	allowedLicenses := utils.LoadAllowedLicenses(input.AllowedLicenses)

	ctx := context.Background()
	referenceManifest, err := store.GetReferenceManifest(ctx, subjectReference, descriptor)
	if err != nil {
		return nil, err
	}

	if len(referenceManifest.Blobs) == 0 {
		return &verifier.VerifierResult{
			Name:      input.Name,
			Type:      verifierType,
			IsSuccess: false,
			Message:   fmt.Sprintf("License Check FAILED: no blobs found for referrer %s@%s", subjectReference.Path, descriptor.Digest.String()),
		}, nil
	}

	for _, blobDesc := range referenceManifest.Blobs {
		refBlob, err := store.GetBlobContent(ctx, subjectReference, blobDesc.Digest)
		if err != nil {
			return nil, err
		}

		spdxDoc, err := utils.BlobToSPDX(refBlob)
		if err != nil {
			return nil, err
		}

		packageLicenses := utils.GetPackageLicenses(*spdxDoc)
		disallowedLicenses := utils.FilterPackageLicenses(packageLicenses, allowedLicenses)

		if len(disallowedLicenses) > 0 {
			return &verifier.VerifierResult{
				Name:      input.Name,
				Type:      verifierType,
				IsSuccess: false,
				Message:   fmt.Sprintf("License Check: FAILED. %s", disallowedLicenses),
			}, nil
		}
	}

	return &verifier.VerifierResult{
		Name:      input.Name,
		Type:      verifierType,
		IsSuccess: true,
		Message:   "License Check: SUCCESS. All packages have allowed licenses",
	}, nil
}
