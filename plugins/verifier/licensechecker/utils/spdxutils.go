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
	"strings"

	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/tagvalue"
)

func BlobToSPDX(bytes []byte) (*spdx.Document, error) {
	raw := string(bytes)
	reader := strings.NewReader(raw)
	return tagvalue.Read(reader)
}

func GetPackageLicenses(doc spdx.Document) []PackageLicense {
	output := make([]PackageLicense, 0, len(doc.Packages))
	for _, p := range doc.Packages {
		output = append(output, PackageLicense{
			PackageName:    p.PackageName,
			PackageLicense: p.PackageLicenseConcluded,
		})
	}
	return output
}

func LoadAllowedLicenses(licenses []string) map[string]struct{} {
	output := map[string]struct{}{}
	for _, license := range licenses {
		output[license] = struct{}{}
	}
	return output
}

func FilterPackageLicenses(packageLicenses []PackageLicense, allowedLicenses map[string]struct{}) []PackageLicense {
	var output []PackageLicense
	for _, packageLicense := range packageLicenses {
		_, ok := allowedLicenses[packageLicense.PackageLicense]
		if !ok {
			output = append(output, packageLicense)
		}
	}
	return output
}
