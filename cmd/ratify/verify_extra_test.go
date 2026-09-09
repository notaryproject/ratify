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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify/v2/internal/store"
	"github.com/notaryproject/ratify/v2/internal/verifier"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	testStoreType          = "cli-test-store"
	testFailingStoreType   = "cli-test-failing-store"
	testVerifierType       = "cli-test-verifier"
	testSubjectRef         = "registry.example/repo:v1"
	testSubjectDigest      = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	testSubjectMediaType   = "application/vnd.oci.image.manifest.v1+json"
	testSubjectArtifactRef = "registry.example/repo@" + testSubjectDigest
)

// errStubStoreResolve is returned by the failing stub store to force
// ValidateArtifact to fail during subject resolution.
var errStubStoreResolve = errors.New("stub store: resolve failed")

// stubStore is a minimal [ratify.Store] used to drive runVerify without a real
// registry. When resolveErr is set, Resolve fails so ValidateArtifact errors.
type stubStore struct {
	resolveErr error
}

func (s *stubStore) Resolve(_ context.Context, _ string) (ocispec.Descriptor, error) {
	if s.resolveErr != nil {
		return ocispec.Descriptor{}, s.resolveErr
	}
	return ocispec.Descriptor{
		MediaType: testSubjectMediaType,
		Digest:    testSubjectDigest,
		Size:      2,
	}, nil
}

func (s *stubStore) ListReferrers(_ context.Context, _ string, _ []string, _ func(referrers []ocispec.Descriptor) error) error {
	return nil
}

func (s *stubStore) FetchBlob(_ context.Context, _ string, _ ocispec.Descriptor) ([]byte, error) {
	return nil, errors.New("stub store: blob not available")
}

func (s *stubStore) FetchManifest(_ context.Context, _ string, _ ocispec.Descriptor) ([]byte, error) {
	return nil, errors.New("stub store: manifest not available")
}

func init() {
	store.Register(testStoreType, func(store.NewOptions) (ratify.Store, error) {
		return &stubStore{}, nil
	})
	store.Register(testFailingStoreType, func(store.NewOptions) (ratify.Store, error) {
		return &stubStore{resolveErr: errStubStoreResolve}, nil
	})
	verifier.Register(testVerifierType, func(opts verifier.NewOptions, _ []string) (ratify.Verifier, error) {
		return &stubVerifier{name: opts.Name}, nil
	})
}

// writeExecutorConfig writes a valid executor configuration that references the
// given store type and returns its path.
func writeExecutorConfig(t *testing.T, storeType string) string {
	t.Helper()
	cfg := map[string]any{
		"executors": []map[string]any{
			{
				"scopes":    []string{"registry.example"},
				"verifiers": []map[string]any{{"name": "stub", "type": testVerifierType}},
				"stores":    []map[string]any{{"type": storeType, "parameters": map[string]any{}}},
			},
		},
	}
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	return path
}

func TestLoadExecutor_Valid(t *testing.T) {
	path := writeExecutorConfig(t, testStoreType)
	scoped, err := loadExecutor(path)
	if err != nil {
		t.Fatalf("unexpected error loading executor: %v", err)
	}
	if scoped == nil {
		t.Fatal("expected a non-nil scoped executor")
	}
}

func TestRunVerify_LoadExecutorError(t *testing.T) {
	cmd := newVerifyCmd()
	cmd.SetOut(new(bytesBuffer))
	opts := &verifyOptions{
		subject:    testSubjectRef,
		output:     outputText,
		configPath: filepath.Join(t.TempDir(), "missing.json"),
	}
	if err := runVerify(cmd, opts); err == nil {
		t.Error("expected an error when the configuration file cannot be loaded")
	}
}

func TestRunVerify_ValidateArtifactError(t *testing.T) {
	cmd := newVerifyCmd()
	cmd.SetOut(new(bytesBuffer))
	cmd.SetContext(context.Background())
	opts := &verifyOptions{
		subject:    testSubjectArtifactRef,
		output:     outputText,
		configPath: writeExecutorConfig(t, testFailingStoreType),
	}
	err := runVerify(cmd, opts)
	if err == nil {
		t.Fatal("expected an error when artifact resolution fails")
	}
	if !strings.Contains(err.Error(), "failed to verify artifact") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunVerify_RendersResult(t *testing.T) {
	cmd := newVerifyCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetContext(context.Background())
	opts := &verifyOptions{
		subject:    testSubjectArtifactRef,
		output:     outputText,
		configPath: writeExecutorConfig(t, testStoreType),
	}
	// The result may be a pass or a fail depending on ratify-go policy defaults;
	// either way runVerify must render the report to the command's output.
	_ = runVerify(cmd, opts)
	if !strings.Contains(buf.String(), "Subject:") {
		t.Errorf("expected rendered report output; got:\n%s", buf.String())
	}
}

func TestNewRenderedReports_SkipsNilEntries(t *testing.T) {
	reports := []*ratify.ValidationReport{
		nil,
		{
			Subject:  testSubjectRef,
			Artifact: ocispec.Descriptor{Digest: testSubjectDigest},
			Results: []*ratify.VerificationResult{
				nil,
				{Verifier: &stubVerifier{name: "notation"}, Description: "ok"},
			},
		},
	}
	rendered := newRenderedReports(reports)
	if len(rendered) != 1 {
		t.Fatalf("expected nil report to be skipped, got %d reports", len(rendered))
	}
	if len(rendered[0].Results) != 1 {
		t.Fatalf("expected nil result to be skipped, got %d results", len(rendered[0].Results))
	}
	if rendered[0].Results[0].Verifier != "notation" {
		t.Errorf("unexpected verifier: %q", rendered[0].Results[0].Verifier)
	}
}

func TestPrintResult_NestedReports(t *testing.T) {
	result := &ratify.ValidationResult{
		Succeeded: true,
		ArtifactReports: []*ratify.ValidationReport{
			{
				Subject:  testSubjectRef,
				Artifact: ocispec.Descriptor{Digest: testSubjectDigest},
				Results: []*ratify.VerificationResult{
					{Verifier: &stubVerifier{name: "notation"}, Description: "signature verified"},
				},
				ArtifactReports: []*ratify.ValidationReport{
					{
						Subject:  testSubjectRef,
						Artifact: ocispec.Descriptor{Digest: "sha256:3333333333333333333333333333333333333333333333333333333333333333"},
						Results: []*ratify.VerificationResult{
							{Verifier: &stubVerifier{name: "cosign"}},
						},
					},
				},
			},
		},
	}
	var buf strings.Builder
	if err := printResult(&buf, testSubjectRef, outputText, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"verifier=notation", "verifier=cosign", "sha256:3333"} {
		if !strings.Contains(out, want) {
			t.Errorf("nested text output missing %q; got:\n%s", want, out)
		}
	}
}
