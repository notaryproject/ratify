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
	"bytes"
	"os"
	"path/filepath"
	"testing"

	jsonLoader "github.com/spdx/tools-golang/json"
)

func TestGetPackageLicenses(t *testing.T) {
	b, _ := os.ReadFile(filepath.Join("../testdata", "syftbom.spdx.json"))
	spdxDoc, _ := jsonLoader.Read(bytes.NewReader(b))

	result := GetPackageLicenses(*spdxDoc)
	if len(result) != 16 {
		t.Fatalf("unexpected packages count, expected 16")
	}
}

func TestContainsLicense(t *testing.T) {
	tests := []struct {
		name                  string
		spdxLicenseExpression string
		disallowed            string
		expected              bool
	}{
		{
			name:                  "exact match",
			spdxLicenseExpression: "MIT",
			disallowed:            "MIT",
			expected:              true,
		},
		{
			name:                  "brackets",
			spdxLicenseExpression: "(MIT)",
			disallowed:            "MIT",
			expected:              true,
		},
		{
			name:                  "exact match with space",
			spdxLicenseExpression: "MPL-2.0 AND LicenseRef-AND AND MIT",
			disallowed:            "MPL",
			expected:              false,
		},
		{
			name:                  "exact match with space",
			spdxLicenseExpression: "MPL-2.0 AND LicenseRef-AND AND MIT",
			disallowed:            "MPL-2.0",
			expected:              true,
		},
		{
			name:                  "exact match with space",
			spdxLicenseExpression: "MIT AND LicenseRef-AND AND MPL-2.0",
			disallowed:            "MPL-2.0",
			expected:              true,
		},
		{
			name:                  "license partial match",
			spdxLicenseExpression: "MIT AND LicenseRef-BSD AND GPL-2.0-or-later",
			disallowed:            "GPL-2.0",
			expected:              false,
		},
		{
			name:                  "license partial match",
			spdxLicenseExpression: "MIT AND (LicenseRef-BSD OR GPL-2.0-or-later)",
			disallowed:            "GPL-2.0-or-later",
			expected:              true,
		},
		{
			name:                  "license partial match",
			spdxLicenseExpression: "MIT AND (LicenseRef-BSD OR GPL-2.0-or-later)",
			disallowed:            "(LicenseRef-BSD OR GPL-2.0-or-later)",
			expected:              true,
		},
	}

	for _, tt := range tests {
		t.Run("test scenario", func(t *testing.T) {
			result := ContainsLicense(tt.spdxLicenseExpression, tt.disallowed)
			if result != tt.expected {
				t.Fatalf("Looking for %v in %v , expected %t, got %t", tt.disallowed, tt.spdxLicenseExpression, tt.expected, result)
			}
		})
	}
}
