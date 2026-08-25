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

package schemavalidation

import (
	"os"
	"testing"
)

var schemaURL = "https://json.schemastore.org/sarif-2.1.0-rtm.5.json"
var schemaFileBytes []byte
var schemaFileMismatchBytes []byte
var schemaFileBadBytes []byte
var trivyScanReport []byte

func init() {
	trivyScanReport, _ = os.ReadFile("./testdata/trivy_scan_report.json")
	schemaFileBytes, _ = os.ReadFile("./schemas/sarif-2.1.0-rtm.5.json")
	schemaFileMismatchBytes, _ = os.ReadFile("./testdata/mismatch_schema.json")
	schemaFileBadBytes, _ = os.ReadFile("./testdata/bad_schema.json")
}

func TestProperSchemaValidates(t *testing.T) {
	expected := true
	result := Validate(schemaURL, trivyScanReport) == nil

	if expected != result {
		t.Logf("expected: %v, got: %v", expected, result)
		t.FailNow()
	}
}

func TestInvalidSchemaFailsValidation(t *testing.T) {
	expected := false
	result := Validate("bad schema", trivyScanReport) == nil

	if expected != result {
		t.Logf("expected: %v, got: %v", expected, result)
		t.FailNow()
	}
}

func TestProperSchemaValidatesFromFile(t *testing.T) {
	expected := true
	result := ValidateAgainstOfflineSchema(schemaFileBytes, trivyScanReport) == nil

	if expected != result {
		t.Logf("expected: %v, got: %v", expected, result)
		t.FailNow()
	}
}

func TestSchemaMismatchFromFile(t *testing.T) {
	expected := false
	result := ValidateAgainstOfflineSchema(schemaFileMismatchBytes, trivyScanReport) == nil

	if expected != result {
		t.Logf("expected: %v, got: %v", expected, result)
		t.FailNow()
	}
}

func TestBadSchemaValidatesFromFile(t *testing.T) {
	expected := false
	result := ValidateAgainstOfflineSchema(schemaFileBadBytes, trivyScanReport) == nil

	if expected != result {
		t.Logf("expected: %v, got: %v", expected, result)
		t.FailNow()
	}
}
