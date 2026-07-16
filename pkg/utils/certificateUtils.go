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

package utils

import (
	"crypto/x509"
	"io/fs"
	"os"
	"strings"

	"path/filepath"

	notationx509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/ratify/v2/pkg/homedir"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Return list of certificates loaded from path
// when path is a directory, this method loads all certs in directory and resolve symlink if needed
func GetCertificatesFromPath(path string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	fileMap := map[string]bool{} //a map to track path of physical files

	path = ReplaceHomeShortcut(path)

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
			if _, ok := fileMap[targetFilePath]; !ok {
				certs, err = loadCertFile(targetFilePath, certs, fileMap)
				if err != nil {
					return errors.Wrap(err, "error reading certificate file "+targetFilePath)
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	logrus.Infof("%v notation verification certificates loaded from path '%v'", len(certs), path)
	return certs, nil
}

func isSymbolicLink(info fs.FileInfo) bool {
	return info.Mode()&os.ModeSymlink != 0
}

func loadCertFile(filePath string, certificate []*x509.Certificate, fileMap map[string]bool) ([]*x509.Certificate, error) {
	cert, certError := notationx509.ReadCertificateFile(filePath) // ReadCertificateFile returns empty if file was not a certificate
	if certError != nil {
		return certificate, certError
	}
	if cert != nil {
		certificate = append(certificate, cert...)
		fileMap[filePath] = true
	}

	return certificate, nil
}

// Replace the shortcut prefix in a path with the home directory
// For example in a unix os, ~/.config/ becomes /home/azureuser/.config after replacement
func ReplaceHomeShortcut(path string) string {
	shortcutPrefix := homedir.GetShortcutString() + string(os.PathSeparator)
	if strings.HasPrefix(path, shortcutPrefix) {
		home := homedir.Get()
		if len(home) > 0 {
			return strings.Replace(path, homedir.GetShortcutString(), home, 1) // replace 1 instance
		}
		logrus.Warningf("Path '%v' replacement failed , value of Home dir '%v'", path, home)
	}
	return path
}
