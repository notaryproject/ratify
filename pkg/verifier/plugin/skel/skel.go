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

package skel

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/common/plugin"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
	storeConfig "github.com/notaryproject/ratify/v2/pkg/referrerstore/config"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore/factory"
	"github.com/notaryproject/ratify/v2/pkg/utils"
	"github.com/notaryproject/ratify/v2/pkg/verifier"
	"github.com/notaryproject/ratify/v2/pkg/verifier/config"
	vp "github.com/notaryproject/ratify/v2/pkg/verifier/plugin"
	"github.com/notaryproject/ratify/v2/pkg/verifier/types"
)

type pcontext struct {
	GetEnviron func(string) string
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
}

type VerifyReference func(args *CmdArgs, subjectReference common.Reference, referenceDescriptor ocispecs.ReferenceDescriptor, referrerStore referrerstore.ReferrerStore) (*verifier.VerifierResult, error)

// CmdArgs describes arguments that are passed when the plugin is invoked
type CmdArgs struct {
	Version    string
	Subject    string
	subjectRef common.Reference
	StdinData  []byte
}

// PluginMain is the core "main" for a plugin which includes error handling.
func PluginMain(name, version string, verifyReference VerifyReference, supportedVersions []string) {
	if e := (&pcontext{
		GetEnviron: os.Getenv,
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
	}).pluginMainCore(name, version, verifyReference, supportedVersions); e != nil {
		if err := e.Print(); err != nil {
			log.Print("Error writing error response to stdout: ", err)
		}
		os.Exit(1)
	}
}

func (pc *pcontext) pluginMainCore(_, version string, verifyReference VerifyReference, supportedVersions []string) *plugin.Error {
	cmd, cmdArgs, err := pc.getCmdArgsFromEnv()
	if err != nil {
		return err
	}

	if err = validateVersion(cmdArgs.Version, supportedVersions); err != nil {
		return err
	}

	input, err := validateAndGetConfig(cmdArgs.StdinData)
	if err != nil {
		return err
	}

	// The below is a workaround to be able to use built-in referrer store plugins from within verifier plugins
	storeConfigs := storeConfig.StoresConfig{
		Version:       version,
		PluginBinDirs: input.StoreConfig.PluginBinDirs,
		Stores:        []storeConfig.StorePluginConfig{input.StoreConfig.Store},
	}
	stores, storeErr := factory.CreateStoresFromConfig(storeConfigs, "")
	if storeErr != nil || stores == nil || len(stores) == 0 {
		return plugin.NewError(types.ErrArgsParsingFailure, fmt.Sprintf("create store from input config failed with error %v", storeErr), "")
	}
	store := stores[0]

	// This is the original implementation for initialization of a referrer store which does not support built-ins
	//store, serr := rp.NewStore(input.StoreConfig.Version, input.StoreConfig.Store, input.StoreConfig.PluginBinDirs)
	//if serr != nil {
	//	return plugin.NewError(types.ErrArgsParsingFailure, fmt.Sprintf("create store from the input config failed with error %v", serr), "")
	//}

	switch cmd {
	case vp.VerifyCommand:
		result, err := verifyReference(cmdArgs, cmdArgs.subjectRef, input.ReferencDesc, store)

		if err != nil {
			return plugin.NewError(types.ErrPluginCmdFailure, fmt.Sprintf("plugin command %s failed", vp.VerifyCommand), err.Error())
		}

		err = types.WriteVerifyResultResult(result, pc.Stdout)
		if err != nil {
			return plugin.NewError(types.ErrIOFailure, "failed to write plugin output", err.Error())
		}

		return nil
	default:
		return plugin.NewError(types.ErrUnknownCommand, fmt.Sprintf("unknown %s: %v", vp.CommandEnvKey, cmd), "")
	}
}

func (pc *pcontext) getCmdArgsFromEnv() (string, *CmdArgs, *plugin.Error) {
	argsMissing := make([]string, 0)

	// #1 Command
	var cmd = pc.GetEnviron(vp.CommandEnvKey)
	if cmd == "" {
		argsMissing = append(argsMissing, vp.CommandEnvKey)
	}

	// #2 Version
	var version = pc.GetEnviron(vp.VersionEnvKey)
	if version == "" {
		argsMissing = append(argsMissing, vp.VersionEnvKey)
	}

	// #3 Subject
	var subject = pc.GetEnviron(vp.SubjectEnvKey)
	if subject == "" {
		argsMissing = append(argsMissing, vp.SubjectEnvKey)
	}

	if len(argsMissing) > 0 {
		joined := strings.Join(argsMissing, ",")
		return "", nil, plugin.NewError(types.ErrMissingEnvironmentVariables, fmt.Sprintf("missing env variables [%s]", joined), "")
	}

	stdinData, err := io.ReadAll(pc.Stdin)
	if err != nil {
		return "", nil, plugin.NewError(types.ErrIOFailure, fmt.Sprintf("error reading from stdin: %v", err), "")
	}

	subRef, err := utils.ParseSubjectReference(subject)
	if err != nil {
		return "", nil, plugin.NewError(types.ErrArgsParsingFailure, fmt.Sprintf("cannot parse subject reference %s", subject), err.Error())
	}

	cmdArgs := &CmdArgs{
		Version:    version,
		Subject:    subject,
		StdinData:  stdinData,
		subjectRef: subRef,
	}

	return cmd, cmdArgs, nil
}

func validateVersion(version string, supportedVersions []string) *plugin.Error {
	for _, v := range supportedVersions {
		// TODO check for compatibility using semversion
		if v == version {
			return nil
		}
	}

	return plugin.NewError(types.ErrVersionNotSupported, fmt.Sprintf("plugin doesn't support version %s", version), "")
}

func validateAndGetConfig(jsonBytes []byte) (*config.PluginInputConfig, *plugin.Error) {
	var input config.PluginInputConfig

	if err := json.Unmarshal(jsonBytes, &input); err != nil {
		return nil, plugin.NewError(types.ErrConfigParsingFailure, fmt.Sprintf("error unmarshall verifier config: %v", err), "")
	}

	if input.Config[types.Name] == "" || input.Config[types.Name] == nil {
		return nil, plugin.NewError(types.ErrInvalidVerifierConfig, "missing verifier name", "")
	}
	return &input, nil
}
