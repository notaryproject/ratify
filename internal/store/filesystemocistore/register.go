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

package filesystemocistore

import (
	"context"
	"fmt"
	"os"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify-go/plugin"
)

const filesystemOCIStoreType = "filesystem-oci-store"

func init() {
	// Register the filesystem OCI store factory
	plugin.RegisterStore(filesystemOCIStoreType, func(ctx context.Context, opts plugin.StoreOptions) (ratify.Store, error) {
		var params map[string]any
		if err := plugin.DecodeParameters(opts.Parameters, &params); err != nil {
			return nil, fmt.Errorf("store parameters must be a map: %w", err)
		}
		if params == nil {
			return nil, fmt.Errorf("store parameters are required")
		}
		pathVal, ok := params["path"]
		if !ok || pathVal == nil {
			return nil, fmt.Errorf("path parameter is required")
		}
		path, ok := pathVal.(string)
		if !ok || path == "" {
			return nil, fmt.Errorf("path parameter must be a non-empty string")
		}
		return ratify.NewOCIStoreFromFS(ctx, os.DirFS(path))
	})
}
