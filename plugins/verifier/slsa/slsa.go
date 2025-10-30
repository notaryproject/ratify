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
	"os"
	"time"

	"github.com/ratify-project/ratify/plugins/verifier/slsa/utils"

	"github.com/ratify-project/ratify/pkg/common"
	"github.com/ratify-project/ratify/pkg/common/plugin/logger"
	"github.com/ratify-project/ratify/pkg/ocispecs"
	"github.com/ratify-project/ratify/pkg/referrerstore"
	_ "github.com/ratify-project/ratify/pkg/referrerstore/oras"
	"github.com/ratify-project/ratify/pkg/verifier"
	"github.com/ratify-project/ratify/pkg/verifier/plugin/skel"
)

const (
	maxBlobs    = 10               // Limit the number of referenceManifest blob, default to 10
	maxBlobSize = 50 * 1024 * 1024 // The max blob size, default to 50MB
)

type PluginConfig struct {
	Name                   string   `json:"name"`
	Type                   string   `json:"type"`
	ExpectedVerifiedLevels []string `json:"expectedVerifiedLevels"`
	ExpectedVerifierID     string   `json:"expectedVerifierId"`
	ExpectedResourceURI    string   `json:"expectedResourceUri"`
}

type PluginInputConfig struct {
	Config PluginConfig `json:"config"`
}

func main() {
	// create a plugin logger
	pluginlogger := logger.NewLogger()

	// output info and Debug to stderr
	pluginlogger.Info("initialized slsa plugin")
	skel.PluginMain("slsa", "1.0.0", VerifyReference, []string{"1.0.0"})

	// By default, the pluginlogger writes to stderr. To change the output, use SetOutput
	pluginlogger.SetOutput(os.Stdout)
}

func parseInput(stdin []byte) (*PluginConfig, error) {
	conf := PluginInputConfig{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse stdin for input: %w", err)
	}

	return &conf.Config, nil
}

func VerifyReference(args *skel.CmdArgs, subjectReference common.Reference, descriptor ocispecs.ReferenceDescriptor, store referrerstore.ReferrerStore) (*verifier.VerifierResult, error) {
	pluginlogger := logger.NewLogger()

	pluginlogger.Infof("begin to VerifyReference for slsa plugin, input is '%v'", string(args.StdinData))

	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		pluginlogger.Infof("slsa verification completed in %v", duration)
	}()
	input, err := parseInput(args.StdinData)
	if err != nil {
		pluginlogger.Warnf("failed to parse input: %v", err)
		return nil, err
	}
	verifierType := input.Name
	if input.Type != "" {
		verifierType = input.Type
	}

	pluginlogger.Infof("verifier type: %s, name: %s", verifierType, input.Name)

	ctx := context.Background()
	referenceManifest, err := store.GetReferenceManifest(ctx, subjectReference, descriptor)
	if err != nil {
		pluginlogger.Warnf("failed to get reference manifest for subject %s: %v", subjectReference, err)
		return nil, err
	}

	pluginlogger.Infof("found %d blobs in reference manifest", len(referenceManifest.Blobs))

	if len(referenceManifest.Blobs) == 0 {
		pluginlogger.Warnf("no blobs found for referrer %s@%s", subjectReference.Path, descriptor.Digest.String())
		return &verifier.VerifierResult{
			Name:      input.Name,
			Type:      verifierType,
			IsSuccess: false,
			Message:   fmt.Sprintf("SLSA attestation verified FAILED: no blobs found for referrer %s@%s", subjectReference.Path, descriptor.Digest.String()),
		}, nil
	}

	// limit the number of blob, default to 10
	if len(referenceManifest.Blobs) > maxBlobs {
		pluginlogger.Warnf("found %d blobs, limiting to first %d to prevent memory issues", len(referenceManifest.Blobs), maxBlobs)
	}
	processedBlobs := 0
	for i, blobDesc := range referenceManifest.Blobs {
		// avoid processing too many blobs
		if processedBlobs >= maxBlobs {
			pluginlogger.Warnf("reached maximum blob limit (%d), stopping processing", maxBlobs)
			break
		}

		pluginlogger.Debugf("processing blob %d/%d, digest: %s, media type: %s", i+1, len(referenceManifest.Blobs), blobDesc.Digest, blobDesc.MediaType)

		// check the size of blob
		if blobDesc.Size > maxBlobSize { // 50MB limit
			pluginlogger.Warnf("skipping large blob %s (size: %d bytes), may cause memory issues", blobDesc.Digest, blobDesc.Size)
			continue
		}

		blobStartTime := time.Now()
		refBlob, err := store.GetBlobContent(ctx, subjectReference, blobDesc.Digest)
		if err != nil {
			pluginlogger.Warnf("failed to get blob content for digest %s: %v", blobDesc.Digest, err)
			return nil, err
		}
		pluginlogger.Debugf("got blob content, size: %d bytes, took %v", len(refBlob), time.Since(blobStartTime))

		vsaStartTime := time.Now()
		_, vsaPred, err := utils.GetVsa(refBlob, utils.GetDefaultVerifier(), utils.GenerateVsaVerificationOptions(input.ExpectedVerifierID, input.ExpectedResourceURI, input.ExpectedVerifiedLevels))
		if err != nil {
			pluginlogger.Warnf("failed to verify vsa from blob: %v (took %v)", err, time.Since(vsaStartTime))
			return &verifier.VerifierResult{
				Name:      input.Name,
				Type:      verifierType,
				IsSuccess: false,
				Message:   fmt.Sprintf("SLSA attestation verified FAILED: can not get VSA %v", err),
			}, nil
		}

		pluginlogger.Debugf("got vsapred with verifier id: %s, result: %s (took %v)",
			vsaPred.GetVerifier().GetId(), vsaPred.GetVerificationResult(), time.Since(vsaStartTime))
		pluginlogger.Debugf("successfully extracted vsa predicate from blob %d", i+1)

		processedBlobs++
	}

	pluginlogger.Info("SLSA attestation verification completed successfully")
	return &verifier.VerifierResult{
		Name:      input.Name,
		Type:      verifierType,
		IsSuccess: true,
		Message:   "SLSA Attestation Check: SUCCESS.",
	}, nil
}
