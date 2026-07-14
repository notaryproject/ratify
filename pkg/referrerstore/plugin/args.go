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
	"fmt"
	"os"

	pluginCommon "github.com/notaryproject/ratify/v2/pkg/common/plugin"
)

// ReferrerStorePluginArgs describes all arguments that are passed when a store plugin is invoked
type ReferrerStorePluginArgs struct {
	Command          string
	Version          string
	SubjectReference string
	PluginArgs       [][2]string
}

var _ pluginCommon.PluginArgs = &ReferrerStorePluginArgs{}

func (args *ReferrerStorePluginArgs) AsEnviron() []string {
	env := os.Environ()
	pluginArgsStr := pluginCommon.Concat(args.PluginArgs)

	// Duplicated values which come first will be overridden, so we must put the
	// custom values in the end to avoid being overridden by the process environments.
	env = append(env,
		fmt.Sprintf("%s=%s", CommandEnvKey, args.Command),
		fmt.Sprintf("%s=%s", SubjectEnvKey, args.SubjectReference),
		fmt.Sprintf("%s=%s", ArgsEnvKey, pluginArgsStr),
		fmt.Sprintf("%s=%s", VersionEnvKey, args.Version),
	)
	return pluginCommon.MergeDuplicateEnviron(env)
}
