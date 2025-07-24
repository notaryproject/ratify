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
	"github.com/notaryproject/ratify/v2/internal/store"
)

const filesystemOCIStoreType = "filesystem-oci-store"

func init() {
	// Register the filesystem OCI store factory
	store.RegisterStoreFactory(filesystemOCIStoreType, func(opts *store.NewOptions) (ratify.Store, error) {
		if opts.Parameters == nil {
			return nil, fmt.Errorf("store parameters are required")
		}
		params, ok := opts.Parameters.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("store parameters must be a map")
		}
		pathVal, ok := params["path"]
		if !ok || pathVal == nil {
			return nil, fmt.Errorf("path parameter is required")
		}
		path, ok := pathVal.(string)
		if !ok || path == "" {
			return nil, fmt.Errorf("path parameter must be a non-empty string")
		}
		return ratify.NewOCIStoreFromFS(context.Background(), os.DirFS(path))
	})
}
