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

package filesystemprovider

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	notationx509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/ratify/v2/internal/verifier/keyprovider"
	"github.com/sirupsen/logrus"
)

const fileSystemProviderName = "files"

// FileSystemProvider is a key provider that loads certificates from the file
// system.
type FileSystemProvider struct {
	certPaths    []string
	certificates []*x509.Certificate
}

func init() {
	keyprovider.RegisterKeyProvider(fileSystemProviderName, func(options any) (keyprovider.KeyProvider, error) {
		raw, err := json.Marshal(options)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal options: %w", err)
		}
		var paths []string
		if err := json.Unmarshal(raw, &paths); err != nil {
			return nil, fmt.Errorf("failed to unmarshal options: %w", err)
		}

		if len(paths) == 0 {
			return nil, fmt.Errorf("no file paths provided")
		}

		// Load certificates during initialization
		var allCertificates []*x509.Certificate
		for _, certPath := range paths {
			certificates, err := loadCertificatesFromPath(certPath)
			if err != nil {
				return nil, fmt.Errorf("failed to load certificates from path %s: %w", certPath, err)
			}
			allCertificates = append(allCertificates, certificates...)
		}

		return &FileSystemProvider{
			certPaths:    paths,
			certificates: allCertificates,
		}, nil
	})
}

// FileSystemProvider implements GetCertificates of [truststore.X509TrustStore]
// interface.
func (f *FileSystemProvider) GetCertificates(_ context.Context) ([]*x509.Certificate, error) {
	// Return cached certificates loaded during initialization
	logrus.Debugf("Returning %d cached certificate(s) from file system", len(f.certificates))
	return f.certificates, nil
}

func (f *FileSystemProvider) GetKeys(_ context.Context) ([]*keyprovider.PublicKey, error) {
	return nil, fmt.Errorf("GetKeys not implemented in FileSystemProvider")
}

func loadCertificatesFromPath(path string) ([]*x509.Certificate, error) {
	logrus.Infof("Loading certificates from path: %s", path)
	var certificates []*x509.Certificate
	fileMap := map[string]struct{}{} //a map to track path of physical files

	err := filepath.Walk(path, func(file string, info os.FileInfo, err error) error {
		targetFileInfo := info
		targetFilePath := file

		if info == nil || err != nil {
			logrus.Warnf("Invalid path '%v' skipped, error %v", file, err)
			return nil
		}

		// In a cluster environment, each mounted file results in a physical file and a symlink
		// check if file is a link and get the actual file path
		if isSymbolicLink(info) {
			targetFilePath, err = filepath.EvalSymlinks(file)
			if err != nil || len(targetFilePath) == 0 {
				logrus.Errorf("Unable to resolve symbolic link %v , error '%v'", file, err)
				return nil
			}

			targetFileInfo, err = os.Lstat(targetFilePath)
			if err != nil {
				logrus.Errorf("error getting file info for path '%v', error '%v'", targetFilePath, err)
				return nil
			}
		}

		// if filepath.EvalSymlinks fails to resolve multi level sym link, skip this file
		if targetFileInfo != nil && !targetFileInfo.IsDir() && !isSymbolicLink(targetFileInfo) {
			if _, ok := fileMap[targetFilePath]; ok {
				return nil
			}
			certs, err := notationx509.ReadCertificateFile(targetFilePath)
			if err != nil {
				return fmt.Errorf("error reading certificate file %s: %w", targetFilePath, err)
			}
			certificates = append(certificates, certs...)
			fileMap[targetFilePath] = struct{}{}
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking the path %s: %w", path, err)
	}
	return certificates, nil
}

func isSymbolicLink(info fs.FileInfo) bool {
	return info.Mode()&os.ModeSymlink != 0
}
