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

package notation

import (
	"context"
	"io/fs"
	"strings"

	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/plugin"
	pl "github.com/notaryproject/notation-plugin-framework-go/plugin"
)

const (
	notationPluginPrefix   = "notation-"
	defaultPluginDirectory = "/.ratify/plugins"
)

// Implements interface defined in https://github.com/notaryproject/notation-go/blob/main/plugin/manager.go#L20
type RatifyPluginManager struct {
	pluginFS dir.SysFS
}

func NewRatifyPluginManager(directory string) *RatifyPluginManager {
	return &RatifyPluginManager{pluginFS: dir.NewSysFS(directory)}
}

// Returns a notation Plugin for the given name if present in the target directory
func (m *RatifyPluginManager) Get(ctx context.Context, name string) (pl.Plugin, error) {
	path, err := m.pluginFS.SysPath(notationPluginPrefix + name)
	if err != nil {
		return nil, err
	}

	// validate and create plugin
	return plugin.NewCLIPlugin(ctx, name, path)
}

// Lists available notation plugins in the target directory
func (m *RatifyPluginManager) List(_ context.Context) ([]string, error) {
	var plugins []string
	err := fs.WalkDir(m.pluginFS, ".", func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		typ := d.Type()
		if typ.IsDir() || !strings.HasPrefix(d.Name(), notationPluginPrefix) {
			// Ignore directories and files that don't start with "notation-"
			return nil
		}

		// add plugin name
		name := strings.ReplaceAll(d.Name(), notationPluginPrefix, "")
		plugins = append(plugins, name)
		return fs.SkipDir
	})

	if err != nil {
		return nil, err
	}

	return plugins, nil
}
