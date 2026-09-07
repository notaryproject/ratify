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
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/notaryproject/ratify-go"
)

// renderedResult is a serializable view of [ratify.ValidationResult].
type renderedResult struct {
	Subject         string            `json:"subject"`
	Succeeded       bool              `json:"succeeded"`
	ArtifactReports []*renderedReport `json:"artifactReports,omitempty"`
}

// renderedReport is a serializable view of [ratify.ValidationReport].
type renderedReport struct {
	Subject         string                  `json:"subject"`
	Artifact        string                  `json:"artifact"`
	Results         []*renderedVerification `json:"results,omitempty"`
	ArtifactReports []*renderedReport       `json:"artifactReports,omitempty"`
}

// renderedVerification is a serializable view of [ratify.VerificationResult].
type renderedVerification struct {
	Verifier    string `json:"verifier"`
	Description string `json:"description,omitempty"`
	Error       string `json:"error,omitempty"`
}

// newRenderedResult converts a [ratify.ValidationResult] into a serializable
// view that is safe to marshal to JSON and render as text.
func newRenderedResult(subject string, src *ratify.ValidationResult) *renderedResult {
	out := &renderedResult{Subject: subject}
	if src == nil {
		return out
	}
	out.Succeeded = src.Succeeded
	out.ArtifactReports = newRenderedReports(src.ArtifactReports)
	return out
}

func newRenderedReports(src []*ratify.ValidationReport) []*renderedReport {
	if len(src) == 0 {
		return nil
	}
	reports := make([]*renderedReport, 0, len(src))
	for _, report := range src {
		if report == nil {
			continue
		}
		rendered := &renderedReport{
			Subject:         report.Subject,
			Artifact:        report.Artifact.Digest.String(),
			ArtifactReports: newRenderedReports(report.ArtifactReports),
		}
		for _, result := range report.Results {
			if result == nil {
				continue
			}
			rendered.Results = append(rendered.Results, newRenderedVerification(result))
		}
		reports = append(reports, rendered)
	}
	return reports
}

func newRenderedVerification(src *ratify.VerificationResult) *renderedVerification {
	rendered := &renderedVerification{Description: src.Description}
	if src.Verifier != nil {
		rendered.Verifier = src.Verifier.Name()
	}
	if src.Err != nil {
		rendered.Error = src.Err.Error()
	}
	return rendered
}

// printResult writes the verification result to w in the requested format.
func printResult(w io.Writer, subject, format string, src *ratify.ValidationResult) error {
	rendered := newRenderedResult(subject, src)
	if format == outputJSON {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(rendered)
	}
	return printResultText(w, rendered)
}

func printResultText(w io.Writer, rendered *renderedResult) error {
	status := "FAILED"
	if rendered.Succeeded {
		status = "SUCCEEDED"
	}
	if _, err := fmt.Fprintf(w, "Subject:   %s\nSucceeded: %t (%s)\n", rendered.Subject, rendered.Succeeded, status); err != nil {
		return err
	}
	if len(rendered.ArtifactReports) == 0 {
		_, err := fmt.Fprintln(w, "No artifact reports were produced.")
		return err
	}
	return printReportsText(w, rendered.ArtifactReports, 1)
}

func printReportsText(w io.Writer, reports []*renderedReport, depth int) error {
	indent := strings.Repeat("  ", depth)
	for _, report := range reports {
		if _, err := fmt.Fprintf(w, "%s- artifact: %s\n", indent, report.Artifact); err != nil {
			return err
		}
		for _, result := range report.Results {
			line := fmt.Sprintf("%s    verifier=%s", indent, result.Verifier)
			if result.Description != "" {
				line += fmt.Sprintf(" description=%q", result.Description)
			}
			if result.Error != "" {
				line += fmt.Sprintf(" error=%q", result.Error)
			}
			if _, err := fmt.Fprintln(w, line); err != nil {
				return err
			}
		}
		if err := printReportsText(w, report.ArtifactReports, depth+1); err != nil {
			return err
		}
	}
	return nil
}
