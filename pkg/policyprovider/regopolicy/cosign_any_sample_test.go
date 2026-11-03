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

package regopolicy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratify-project/ratify/pkg/executor/types"
	vt "github.com/ratify-project/ratify/pkg/verifier/types"
)

const (
	cosignAnyPolicySample  = "config_v1beta1_policy_rego_cosign_any.yaml"
	cosignLegacyType       = "application/vnd.dev.cosign.artifact.sig.v1+json"
	cosignBundleType       = "application/vnd.dev.sigstore.bundle.v0.3+json"
	notationSignatureType  = "application/vnd.cncf.notary.signature"
	sbomArtifactType       = "application/spdx+json"
	regoPolicyBlockStarter = "    policy: |"
)

// loadSamplePolicy extracts the rego policy block from a sample Policy CR.
func loadSamplePolicy(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "samples", "clustered", "policy", name))
	if err != nil {
		t.Fatalf("failed to read sample policy: %v", err)
	}
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	var policy []string
	inPolicy := false
	for _, line := range lines {
		if line == regoPolicyBlockStarter {
			inPolicy = true
			continue
		}
		if inPolicy {
			policy = append(policy, strings.TrimPrefix(line, "      "))
		}
	}
	if len(policy) == 0 {
		t.Fatalf("no rego policy found in sample %s", name)
	}
	return strings.Join(policy, "\n")
}

func report(artifactType string, results ...bool) types.NestedVerifierReport {
	r := types.NestedVerifierReport{
		ArtifactType:    artifactType,
		VerifierReports: []vt.VerifierResult{},
		NestedReports:   []types.NestedVerifierReport{},
	}
	for _, result := range results {
		r.VerifierReports = append(r.VerifierReports, vt.VerifierResult{IsSuccess: result})
	}
	return r
}

func TestCosignAnySamplePolicy(t *testing.T) {
	provider, err := (&Factory{}).Create(map[string]interface{}{
		"name":   "regopolicy",
		"policy": loadSamplePolicy(t, cosignAnyPolicySample),
	})
	if err != nil {
		t.Fatalf("failed to create policy from sample: %v", err)
	}

	sbomWithFailedSignature := report(sbomArtifactType, true)
	sbomWithFailedSignature.NestedReports = append(sbomWithFailedSignature.NestedReports, report(notationSignatureType, false))

	testCases := []struct {
		name    string
		reports []interface{}
		valid   bool
	}{
		{
			name:    "no reports",
			reports: []interface{}{},
			valid:   false,
		},
		{
			name:    "legacy signature only",
			reports: []interface{}{report(cosignLegacyType, true)},
			valid:   true,
		},
		{
			name:    "bundle signature only",
			reports: []interface{}{report(cosignBundleType, true)},
			valid:   true,
		},
		{
			name:    "valid legacy signature and invalid bundle",
			reports: []interface{}{report(cosignLegacyType, true), report(cosignBundleType, false)},
			valid:   true,
		},
		{
			name:    "invalid legacy signature and valid bundle",
			reports: []interface{}{report(cosignLegacyType, false), report(cosignBundleType, true)},
			valid:   true,
		},
		{
			name:    "all cosign signatures invalid",
			reports: []interface{}{report(cosignLegacyType, false), report(cosignBundleType, false)},
			valid:   false,
		},
		{
			name:    "cosign signature without verifier report",
			reports: []interface{}{report(cosignBundleType)},
			valid:   false,
		},
		{
			name:    "no cosign signature",
			reports: []interface{}{report(notationSignatureType, true)},
			valid:   false,
		},
		{
			name:    "valid cosign signature and invalid other artifact",
			reports: []interface{}{report(cosignBundleType, true), report(notationSignatureType, false)},
			valid:   false,
		},
		{
			name:    "valid cosign signature and other artifact without verifier report",
			reports: []interface{}{report(cosignBundleType, true), report(sbomArtifactType)},
			valid:   false,
		},
		{
			name:    "valid cosign signature and other artifact with invalid nested report",
			reports: []interface{}{report(cosignBundleType, true), sbomWithFailedSignature},
			valid:   false,
		},
		{
			name:    "valid cosign signature and valid other artifact",
			reports: []interface{}{report(cosignLegacyType, true), report(notationSignatureType, true)},
			valid:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if valid := provider.OverallVerifyResult(context.Background(), tc.reports); valid != tc.valid {
				t.Fatalf("valid = %v, expected %v", valid, tc.valid)
			}
		})
	}
}
