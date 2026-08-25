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
	"encoding/json"
	"fmt"
	"os"

	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/common/plugin/logger"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
	"github.com/notaryproject/ratify/v2/pkg/verifier"
	"github.com/notaryproject/ratify/v2/pkg/verifier/plugin/skel"
)

type PluginConfig struct {
	Name string `json:"name"`
	Type string `json:"type"`
	// config specific to the plugin
}

type PluginInputConfig struct {
	Config PluginConfig `json:"config"`
}

func main() {
	// create a plugin logger
	pluginlogger := logger.NewLogger()

	// info and debug default to stdout
	pluginlogger.Info("initialized plugin")
	pluginlogger.Debugf("plugin %s %s", "sample", "1.0.0")

	skel.PluginMain("sample", "1.0.0", VerifyReference, []string{"1.0.0"})

	// SetOutput can redirect any of the loggers to a different writer.
	pluginlogger.SetOutput(os.Stderr)
	pluginlogger.Warn("example warning message...")
}

func parseInput(stdin []byte) (*PluginConfig, error) {
	conf := PluginInputConfig{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse stdin for the input: %w", err)
	}

	return &conf.Config, nil
}

func VerifyReference(args *skel.CmdArgs, _ common.Reference, referenceDescriptor ocispecs.ReferenceDescriptor, _ referrerstore.ReferrerStore) (*verifier.VerifierResult, error) {
	input, err := parseInput(args.StdinData)
	if err != nil {
		return nil, err
	}
	verifierType := input.Name
	if input.Type != "" {
		verifierType = input.Type
	}

	return &verifier.VerifierResult{
		Name:      input.Name,
		Type:      verifierType,
		IsSuccess: referenceDescriptor.Size > 0,
		Message:   "Sample verification success",
	}, nil
}
