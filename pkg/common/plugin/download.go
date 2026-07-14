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
	"io"
	"net/http"
	"os"
	"time"

	"github.com/notaryproject/ratify/v2/internal/version"
	"github.com/notaryproject/ratify/v2/pkg/common/oras/authprovider"
	commonutils "github.com/notaryproject/ratify/v2/pkg/common/utils"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

type PluginSource struct { //nolint:revive // ignore linter to have unique type name
	Artifact     string                          `json:"artifact"`
	AuthProvider authprovider.AuthProviderConfig `json:"authProvider,omitempty"`
}

func ParsePluginSource(source interface{}) (PluginSource, error) {
	var pluginSource PluginSource

	// parse to/from json
	sourceBytes, err := json.Marshal(source)
	if err != nil {
		return pluginSource, err
	}

	err = json.Unmarshal(sourceBytes, &pluginSource)
	if err != nil {
		return pluginSource, err
	}

	return pluginSource, nil
}

func DownloadPlugin(source PluginSource, targetPath string) error {
	ctx := context.TODO()

	// initialize a repository
	repository, err := remote.NewRepository(source.Artifact)
	if err != nil {
		return err
	}

	repository.Client = &auth.Client{
		Client: &http.Client{Timeout: 10 * time.Second, Transport: http.DefaultTransport.(*http.Transport).Clone()},
		Header: http.Header{
			"User-Agent": {version.UserAgent},
		},
		Cache: auth.NewCache(),
		Credential: func(ctx context.Context, registry string) (auth.Credential, error) {
			authProvider, err := authprovider.CreateAuthProviderFromConfig(source.AuthProvider)
			if err != nil {
				return auth.EmptyCredential, err
			}

			authConfig, err := authProvider.Provide(ctx, registry)
			if err != nil {
				return auth.EmptyCredential, err
			}

			if authConfig.Username != "" || authConfig.Password != "" || authConfig.IdentityToken != "" {
				return auth.Credential{
					Username:     authConfig.Username,
					Password:     authConfig.Password,
					RefreshToken: authConfig.IdentityToken,
				}, nil
			}
			return auth.EmptyCredential, nil
		},
	}

	// read the reference manifest
	referenceManifestDescriptor, err := repository.Resolve(ctx, source.Artifact)
	if err != nil {
		return err
	}
	logrus.Debugf("Resolved plugin manifest: %v", referenceManifestDescriptor)

	manifestReader, err := repository.Fetch(ctx, referenceManifestDescriptor)
	if err != nil {
		return err
	}

	manifestBytes, err := io.ReadAll(manifestReader)
	if err != nil {
		return err
	}

	referenceManifest := ocispecs.ReferenceManifest{}
	// marshal manifest bytes into reference manifest descriptor
	switch referenceManifestDescriptor.MediaType {
	case oci.MediaTypeImageManifest:
		var imageManifest oci.Manifest
		if err := json.Unmarshal(manifestBytes, &imageManifest); err != nil {
			return err
		}
		referenceManifest = commonutils.OciManifestToReferenceManifest(imageManifest)
	case ocispecs.MediaTypeArtifactManifest:
		if err := json.Unmarshal(manifestBytes, &referenceManifest); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported manifest media type: %s", referenceManifestDescriptor.MediaType)
	}

	if len(referenceManifest.Blobs) == 0 {
		return fmt.Errorf("no blobs found in the manifest")
	}

	// download the first blob to the target path
	logrus.Debugf("Downloading blob %s", referenceManifest.Blobs[0].Digest.String())
	_, blobReader, err := repository.Blobs().FetchReference(ctx, referenceManifest.Blobs[0].Digest.String())
	if err != nil {
		return err
	}

	logrus.Debugf("writing plugin bytes to %s", targetPath)
	pluginFile, err := os.Create(targetPath)
	if err != nil {
		return err
	}

	defer pluginFile.Close()
	_, err = io.Copy(pluginFile, blobReader)
	if err != nil {
		return err
	}

	// mark the plugin as executable
	logrus.Debugf("marking %s as executable", targetPath)
	err = os.Chmod(targetPath, 0700)
	if err != nil {
		return err
	}

	return nil
}
