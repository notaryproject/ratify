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

// Internal types that stores extracted SBOM information
// "name": "alpine-baselayout",
// "SPDXID": "SPDXRef-Package-apk-alpine-baselayout-92b19c7750fb559d",
// "versionInfo": "3.4.0-r0",
// "originator": "Person: Natanael Copa \u003cncopa@alpinelinux.org\u003e",
// "downloadLocation": "https://git.alpinelinux.org/cgit/aports/tree/main/alpine-baselayout",
// "sourceInfo": "acquired package info from APK DB: /lib/apk/db/installed",
// "licenseConcluded": "GPL-2.0-only",
// This will translate to a PackageLicense obj with the following fields:
// Name: alpine-baselayout
// Version: 3.4.0-r0
// License: GPL-2.0-only (maps to licenseConcluded)
type PackageLicense struct {
	Name    string
	Version string
	License string
}

// Internal types that stores extracted Name and Version of package
// "name": "alpine-baselayout",
// "SPDXID": "SPDXRef-Package-apk-alpine-baselayout-92b19c7750fb559d",
// "versionInfo": "3.4.0-r0",
// "originator": "Person: Natanael Copa \u003cncopa@alpinelinux.org\u003e",
// "downloadLocation": "https://git.alpinelinux.org/cgit/aports/tree/main/alpine-baselayout",
// "sourceInfo": "acquired package info from APK DB: /lib/apk/db/installed",
// "licenseConcluded": "GPL-2.0-only",
// This will translate to a PackageInfo obj with the following fields:
// Name: alpine-baselayout
// Version: 3.4.0-r0

type PackageInfo struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}
