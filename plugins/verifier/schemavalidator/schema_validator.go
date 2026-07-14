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

	re "github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
	_ "github.com/notaryproject/ratify/v2/pkg/referrerstore/oras"
	"github.com/notaryproject/ratify/v2/pkg/verifier"
	"github.com/notaryproject/ratify/v2/pkg/verifier/plugin/skel"
	"github.com/notaryproject/ratify/v2/plugins/verifier/schemavalidator/schemavalidation"
)

type PluginConfig struct {
	Name    string            `json:"name"`
	Type    string            `json:"type"`
	Schemas map[string]string `json:"schemas"`
}

type PluginInputConfig struct {
	Config PluginConfig `json:"config"`
}

func main() {
	skel.PluginMain("schemavalidator", "1.0.0", VerifyReference, []string{"1.0.0"})
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
	schemaMap := input.Schemas
	ctx := context.Background()

	referenceManifest, err := referrerStore.GetReferenceManifest(ctx, subjectReference, referenceDescriptor)
	if err != nil {
		return nil, fmt.Errorf("error fetching reference manifest for subject: %s reference descriptor: %v", subjectReference, referenceDescriptor.Descriptor)
	}

	if len(referenceManifest.Blobs) == 0 {
		noBlobErr := re.ErrorCodeVerifyPluginFailure.WithDetail(fmt.Sprintf("No blobs found for referrer %s@%s.", subjectReference.Path, referenceDescriptor.Digest.String()))
		result := verifier.NewVerifierResult("", input.Name, verifierType, "", false, &noBlobErr, nil)
		return &result, nil
	}

	for _, blobDesc := range referenceManifest.Blobs {
		refBlob, err := referrerStore.GetBlobContent(ctx, subjectReference, blobDesc.Digest)
		if err != nil {
			return nil, fmt.Errorf("error fetching blob for subject:[%s] digest:[%s]", subjectReference, blobDesc.Digest)
		}

		err = processMediaType(schemaMap, blobDesc.MediaType, refBlob)
		if err != nil {
			verifierErr := re.ErrorCodeVerifyPluginFailure.WithDetail(fmt.Sprintf("schema validation failed for digest:[%s], media type:[%s].", blobDesc.Digest, blobDesc.MediaType)).WithError(err)
			result := verifier.NewVerifierResult("", input.Name, verifierType, "", false, &verifierErr, nil)
			return &result, nil
		}
	}

	result := verifier.NewVerifierResult("", input.Name, verifierType, "schema validation passed for configured media types", true, nil, nil)
	return &result, nil
}

func processMediaType(schemaMap map[string]string, mediaType string, refBlob []byte) error {
	if ok := len(schemaMap[mediaType]) > 0; ok {
		return schemavalidation.Validate(schemaMap[mediaType], refBlob)
	}
	return fmt.Errorf("media type not configured for plugin:[%s]", mediaType)
}
