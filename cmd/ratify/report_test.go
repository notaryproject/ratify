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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/notaryproject/ratify-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// stubVerifier is a minimal [ratify.Verifier] implementation used to populate
// verification results in tests.
type stubVerifier struct {
	name string
}

func (s *stubVerifier) Name() string                       { return s.name }
func (s *stubVerifier) Type() string                       { return "stub" }
func (s *stubVerifier) Verifiable(ocispec.Descriptor) bool { return true }
func (s *stubVerifier) Verify(context.Context, *ratify.VerifyOptions) (*ratify.VerificationResult, error) {
	return nil, nil
}

func sampleResult() *ratify.ValidationResult {
	return &ratify.ValidationResult{
		Succeeded: true,
		ArtifactReports: []*ratify.ValidationReport{
			{
				Subject: "registry.example/repo:v1",
				Artifact: ocispec.Descriptor{
					Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
				},
				Results: []*ratify.VerificationResult{
					{
						Verifier:    &stubVerifier{name: "notation"},
						Description: "signature verified",
					},
					{
						Verifier: &stubVerifier{name: "cosign"},
						Err:      errors.New("signature not found"),
					},
				},
			},
		},
	}
}

func TestNewRenderedResult(t *testing.T) {
	rendered := newRenderedResult("registry.example/repo:v1", sampleResult())
	if !rendered.Succeeded {
		t.Error("expected rendered result to be succeeded")
	}
	if rendered.Subject != "registry.example/repo:v1" {
		t.Errorf("unexpected subject: %q", rendered.Subject)
	}
	if len(rendered.ArtifactReports) != 1 {
		t.Fatalf("expected 1 artifact report, got %d", len(rendered.ArtifactReports))
	}
	report := rendered.ArtifactReports[0]
	if len(report.Results) != 2 {
		t.Fatalf("expected 2 verification results, got %d", len(report.Results))
	}
	if report.Results[0].Verifier != "notation" || report.Results[0].Description != "signature verified" {
		t.Errorf("unexpected first result: %+v", report.Results[0])
	}
	if report.Results[1].Verifier != "cosign" || report.Results[1].Error != "signature not found" {
		t.Errorf("unexpected second result: %+v", report.Results[1])
	}
}

func TestNewRenderedResult_Nil(t *testing.T) {
	rendered := newRenderedResult("registry.example/repo:v1", nil)
	if rendered.Succeeded {
		t.Error("expected nil result to render as not succeeded")
	}
	if rendered.Subject != "registry.example/repo:v1" {
		t.Errorf("unexpected subject: %q", rendered.Subject)
	}
	if rendered.ArtifactReports != nil {
		t.Errorf("expected no artifact reports, got %v", rendered.ArtifactReports)
	}
}

func TestPrintResult_Text(t *testing.T) {
	var buf bytes.Buffer
	if err := printResult(&buf, "registry.example/repo:v1", outputText, sampleResult()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"SUCCEEDED", "verifier=notation", "verifier=cosign", "signature not found"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q; got:\n%s", want, out)
		}
	}
}

func TestPrintResult_JSON(t *testing.T) {
	var buf bytes.Buffer
	if err := printResult(&buf, "registry.example/repo:v1", outputJSON, sampleResult()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var decoded renderedResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("failed to decode JSON output: %v", err)
	}
	if !decoded.Succeeded {
		t.Error("expected decoded result to be succeeded")
	}
	if len(decoded.ArtifactReports) != 1 || len(decoded.ArtifactReports[0].Results) != 2 {
		t.Errorf("unexpected decoded structure: %+v", decoded)
	}
}

func TestPrintResult_TextNoReports(t *testing.T) {
	var buf bytes.Buffer
	result := &ratify.ValidationResult{Succeeded: false}
	if err := printResult(&buf, "registry.example/repo:v1", outputText, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "FAILED") {
		t.Errorf("expected FAILED status; got:\n%s", out)
	}
	if !strings.Contains(out, "No artifact reports") {
		t.Errorf("expected no-reports notice; got:\n%s", out)
	}
}
