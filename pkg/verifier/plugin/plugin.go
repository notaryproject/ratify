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

package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	re "github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/pkg/common"
	pluginCommon "github.com/notaryproject/ratify/v2/pkg/common/plugin"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
	rc "github.com/notaryproject/ratify/v2/pkg/referrerstore/config"
	"github.com/notaryproject/ratify/v2/pkg/verifier"
	"github.com/notaryproject/ratify/v2/pkg/verifier/config"
	"github.com/notaryproject/ratify/v2/pkg/verifier/types"
)

// VerifierPlugin describes a verifier that is implemented by invoking the plugins
type VerifierPlugin struct {
	name             string
	verifierType     string
	artifactTypes    []string
	nestedReferences []string
	version          string
	path             []string
	rawConfig        config.VerifierConfig
	executor         pluginCommon.Executor
}

// NewVerifier creates a new verifier from the given configuration
func NewVerifier(version string, verifierConfig config.VerifierConfig, pluginPaths []string) (verifier.ReferenceVerifier, error) {
	verifierName, ok := verifierConfig[types.Name]
	if !ok {
		return nil, re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("failed to find verifier name in the verifier config with key: %s", types.Name))
	}
	verifierType := ""
	if _, ok := verifierConfig[types.Type]; ok {
		verifierType = fmt.Sprintf("%s", verifierConfig[types.Type])
	}

	var nestedReferences []string
	if vs, ok := verifierConfig[types.NestedReferences]; ok {
		nestedReferences = strings.Split(fmt.Sprintf("%s", vs), ",")
	}

	var artifactTypes []string
	if at, ok := verifierConfig[types.ArtifactTypes]; ok {
		artifactTypes = strings.Split(fmt.Sprintf("%s", at), ",")
	}

	if len(artifactTypes) == 0 {
		artifactTypes = append(artifactTypes, "*")
	}

	return &VerifierPlugin{
		name:             fmt.Sprintf("%s", verifierName),
		verifierType:     verifierType,
		version:          version,
		path:             pluginPaths,
		rawConfig:        verifierConfig,
		artifactTypes:    artifactTypes,
		nestedReferences: nestedReferences,
		executor:         &pluginCommon.DefaultExecutor{Stderr: os.Stderr},
	}, nil
}

func (vp *VerifierPlugin) CanVerify(_ context.Context, referenceDescriptor ocispecs.ReferenceDescriptor) bool {
	for _, at := range vp.artifactTypes {
		if at == "*" || at == referenceDescriptor.ArtifactType {
			return true
		}
	}
	return false
}

func (vp *VerifierPlugin) Name() string {
	return vp.name
}

func (vp *VerifierPlugin) Type() string {
	return vp.verifierType
}

func (vp *VerifierPlugin) Verify(ctx context.Context,
	subjectReference common.Reference,
	referenceDescriptor ocispecs.ReferenceDescriptor,
	store referrerstore.ReferrerStore) (verifier.VerifierResult, error) {
	referrerStoreConfig := store.GetConfig()
	vr, err := vp.verifyReference(ctx, subjectReference, referenceDescriptor, referrerStoreConfig)
	if err != nil {
		return verifier.VerifierResult{IsSuccess: false}, err
	}

	return *vr, nil
}

func (vp *VerifierPlugin) verifyReference(
	ctx context.Context,
	subjectReference common.Reference,
	referenceDescriptor ocispecs.ReferenceDescriptor,
	referrerStoreConfig *rc.StoreConfig) (*verifier.VerifierResult, error) {
	verifierTypeStr := vp.name
	if vp.verifierType != "" {
		verifierTypeStr = vp.verifierType
	}
	pluginPath, err := vp.executor.FindInPaths(verifierTypeStr, vp.path)
	if err != nil {
		return nil, re.ErrorCodePluginNotFound.NewError(re.Verifier, vp.name, re.EmptyLink, err, nil, re.HideStackTrace)
	}

	pluginArgs := VerifierPluginArgs{
		Command:          VerifyCommand,
		Version:          vp.version,
		SubjectReference: subjectReference.String(),
	}

	inputConfig := config.PluginInputConfig{
		Config:       vp.rawConfig,
		StoreConfig:  *referrerStoreConfig,
		ReferencDesc: referenceDescriptor,
	}

	verifierConfigBytes, err := json.Marshal(inputConfig)
	if err != nil {
		return nil, re.ErrorCodeConfigInvalid.NewError(re.Verifier, vp.name, re.EmptyLink, err, nil, re.HideStackTrace)
	}

	stdoutBytes, err := vp.executor.ExecutePlugin(ctx, pluginPath, nil, verifierConfigBytes, pluginArgs.AsEnviron())
	if err != nil {
		return nil, re.ErrorCodeVerifyPluginFailure.NewError(re.Verifier, vp.name, re.EmptyLink, err, nil, re.HideStackTrace)
	}

	result, err := types.GetVerifierResult(stdoutBytes)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (vp *VerifierPlugin) GetNestedReferences() []string {
	return vp.nestedReferences
}
