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
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// schemaURL is populated by TestMain with the address of a local test server
// that serves the vendored SARIF schema. The tests deliberately do not point at
// a live schema host: doing so makes the unit tests depend on the network and on
// a third party's ability to publish a breaking change at any moment.
var schemaURL string
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

// TestMain serves the vendored schema over a local HTTP server so that the
// "online" code path is still exercised end to end, but hermetically.
func TestMain(m *testing.M) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(schemaFileBytes)
	}))
	schemaURL = server.URL + "/sarif-2.1.0-rtm.5.json"

	code := m.Run()

	server.Close()
	os.Exit(code)
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
