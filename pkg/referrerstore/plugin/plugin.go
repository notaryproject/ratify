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

	"github.com/notaryproject/ratify/v2/pkg/common"
	pluginCommon "github.com/notaryproject/ratify/v2/pkg/common/plugin"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore/config"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore/types"
	"github.com/opencontainers/go-digest"
)

// StorePlugin describes a store that is implemented by invoking the plugins
type StorePlugin struct {
	name      string
	version   string
	path      []string
	rawConfig config.StorePluginConfig
	executor  pluginCommon.Executor
}

func NewStore(version string, storeConfig config.StorePluginConfig, pluginPaths []string) (referrerstore.ReferrerStore, error) {
	storeName, ok := storeConfig[types.Name]
	if !ok {
		return nil, fmt.Errorf("failed to find store name in the stores config with key %s", "name")
	}

	return &StorePlugin{
		name:      fmt.Sprintf("%s", storeName),
		version:   version,
		path:      pluginPaths,
		rawConfig: storeConfig,
		executor:  &pluginCommon.DefaultExecutor{Stderr: os.Stderr},
	}, nil
}

func (sp *StorePlugin) ListReferrers(ctx context.Context, subjectReference common.Reference, artifactTypes []string, nextToken string, _ *ocispecs.SubjectDescriptor) (referrerstore.ListReferrersResult, error) {
	pluginPath, err := sp.executor.FindInPaths(sp.name, sp.path)
	if err != nil {
		return referrerstore.ListReferrersResult{}, err
	}

	args := [][2]string{
		{"nextToken", nextToken},
		{"artifactTypes", strings.Join(artifactTypes, ",")},
	}

	pluginArgs := ReferrerStorePluginArgs{
		Command:          ListReferrersCommand,
		Version:          sp.version,
		SubjectReference: subjectReference.String(),
		PluginArgs:       args,
	}

	storeConfigBytes, err := json.Marshal(sp.rawConfig)
	if err != nil {
		return referrerstore.ListReferrersResult{}, err
	}

	// TODO std writer
	stdoutBytes, err := sp.executor.ExecutePlugin(ctx, pluginPath, nil, storeConfigBytes, pluginArgs.AsEnviron())
	if err != nil {
		return referrerstore.ListReferrersResult{}, err
	}

	listResult, err := types.GetListReferrersResult(stdoutBytes)
	if err != nil {
		return referrerstore.ListReferrersResult{}, err
	}

	return listResult, nil
}

func (sp *StorePlugin) Name() string {
	return sp.name
}

func (sp *StorePlugin) GetBlobContent(ctx context.Context, subjectReference common.Reference, digest digest.Digest) ([]byte, error) {
	pluginPath, err := sp.executor.FindInPaths(sp.name, sp.path)
	if err != nil {
		return nil, err
	}

	args := [][2]string{
		{"digest", digest.String()},
	}

	pluginArgs := ReferrerStorePluginArgs{
		Command:          GetBlobContentCommand,
		Version:          sp.version,
		SubjectReference: subjectReference.String(),
		PluginArgs:       args,
	}

	storeConfigBytes, err := json.Marshal(sp.rawConfig)
	if err != nil {
		return nil, err
	}

	stdoutBytes, err := sp.executor.ExecutePlugin(ctx, pluginPath, nil, storeConfigBytes, pluginArgs.AsEnviron())
	if err != nil {
		return nil, err
	}

	return stdoutBytes, nil
}

func (sp *StorePlugin) GetReferenceManifest(ctx context.Context, subjectReference common.Reference, referenceDesc ocispecs.ReferenceDescriptor) (ocispecs.ReferenceManifest, error) {
	pluginPath, err := sp.executor.FindInPaths(sp.name, sp.path)
	if err != nil {
		return ocispecs.ReferenceManifest{}, err
	}

	args := [][2]string{
		{"digest", referenceDesc.Digest.String()},
	}

	pluginArgs := ReferrerStorePluginArgs{
		Command:          GetRefManifestCommand,
		Version:          sp.version,
		SubjectReference: subjectReference.String(),
		PluginArgs:       args,
	}

	storeConfigBytes, err := json.Marshal(sp.rawConfig)
	if err != nil {
		return ocispecs.ReferenceManifest{}, err
	}

	// TODO std writer
	stdoutBytes, err := sp.executor.ExecutePlugin(ctx, pluginPath, nil, storeConfigBytes, pluginArgs.AsEnviron())
	if err != nil {
		return ocispecs.ReferenceManifest{}, err
	}

	manifest, err := types.GetReferenceManifestResult(stdoutBytes)
	if err != nil {
		return ocispecs.ReferenceManifest{}, err
	}

	return manifest, nil
}

func (sp *StorePlugin) GetSubjectDescriptor(ctx context.Context, subjectReference common.Reference) (*ocispecs.SubjectDescriptor, error) {
	pluginPath, err := sp.executor.FindInPaths(sp.name, sp.path)
	if err != nil {
		return nil, err
	}

	pluginArgs := ReferrerStorePluginArgs{
		Command:          GetSubjectDescriptor,
		Version:          sp.version,
		SubjectReference: subjectReference.String(),
		PluginArgs:       [][2]string{},
	}

	storeConfigBytes, err := json.Marshal(sp.rawConfig)
	if err != nil {
		return nil, err
	}

	// TODO std writer
	stdoutBytes, err := sp.executor.ExecutePlugin(ctx, pluginPath, nil, storeConfigBytes, pluginArgs.AsEnviron())
	if err != nil {
		return nil, err
	}

	desc, err := types.GetSubjectDescriptorResult(stdoutBytes)
	if err != nil {
		return nil, err
	}

	return desc, nil
}

func (sp *StorePlugin) GetConfig() *config.StoreConfig {
	return &config.StoreConfig{
		Version:       sp.version,
		PluginBinDirs: sp.path,
		Store:         sp.rawConfig,
	}
}

func (sp *StorePlugin) GetPath() []string {
	return sp.path
}
