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

package core

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	ratifyerrors "github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/pkg/common"
	e "github.com/notaryproject/ratify/v2/pkg/executor"
	exConfig "github.com/notaryproject/ratify/v2/pkg/executor/config"
	"github.com/notaryproject/ratify/v2/pkg/executor/types"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/policyprovider"
	policyConfig "github.com/notaryproject/ratify/v2/pkg/policyprovider/configpolicy"
	policyTypes "github.com/notaryproject/ratify/v2/pkg/policyprovider/types"
	pt "github.com/notaryproject/ratify/v2/pkg/policyprovider/types"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
	storeConfig "github.com/notaryproject/ratify/v2/pkg/referrerstore/config"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore/mocks"
	"github.com/notaryproject/ratify/v2/pkg/verifier"
	"github.com/opencontainers/go-digest"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	testArtifactType1 = "test-type1"
	testArtifactType2 = "test-type2"
	subject1          = "localhost:5000/net-monitor:v1"
	subjectDigest     = "sha256:6a5a5368e0c2d3e5909184fa28ddfd56072e7ff3ee9a945876f7eee5896ef5bb"
	signatureDigest   = "sha256:9f13e0ac480cf86a5c9ec5d173001bbb6ec455f501f1812f0b0ad1f3468e8cfa"
	artifactType      = "testArtifactType"
)

type mockPolicyProvider struct {
	result     bool
	policyType string
}

func (p *mockPolicyProvider) VerifyNeeded(_ context.Context, _ common.Reference, _ ocispecs.ReferenceDescriptor) bool {
	return true
}

func (p *mockPolicyProvider) ContinueVerifyOnFailure(_ context.Context, _ common.Reference, _ ocispecs.ReferenceDescriptor, _ types.VerifyResult) bool {
	return true
}

func (p *mockPolicyProvider) ErrorToVerifyResult(_ context.Context, _ string, _ error) types.VerifyResult {
	return types.VerifyResult{}
}

func (p *mockPolicyProvider) OverallVerifyResult(_ context.Context, _ []interface{}) bool {
	return p.result
}

func (p *mockPolicyProvider) GetPolicyType(_ context.Context) string {
	if p.policyType == "" {
		return pt.ConfigPolicy
	}
	return pt.RegoPolicy
}

type mockStore struct {
	referrers map[string][]ocispecs.ReferenceDescriptor
}

func (s *mockStore) Name() string {
	return "mockStore"
}

func (s *mockStore) ListReferrers(_ context.Context, _ common.Reference, _ []string, _ string, subjectDesc *ocispecs.SubjectDescriptor) (referrerstore.ListReferrersResult, error) {
	if s.referrers == nil {
		return referrerstore.ListReferrersResult{}, errors.New("some error happened")
	}
	if _, ok := s.referrers[subjectDesc.Digest.String()]; ok {
		return referrerstore.ListReferrersResult{
			NextToken: "",
			Referrers: s.referrers[subjectDesc.Digest.String()],
		}, nil
	}
	return referrerstore.ListReferrersResult{}, nil
}

func (s *mockStore) GetBlobContent(_ context.Context, _ common.Reference, _ digest.Digest) ([]byte, error) {
	return nil, nil
}

func (s *mockStore) GetReferenceManifest(_ context.Context, _ common.Reference, _ ocispecs.ReferenceDescriptor) (ocispecs.ReferenceManifest, error) {
	return ocispecs.ReferenceManifest{}, nil
}

func (s *mockStore) GetConfig() *storeConfig.StoreConfig {
	return nil
}

func (s *mockStore) GetSubjectDescriptor(_ context.Context, subjectReference common.Reference) (*ocispecs.SubjectDescriptor, error) {
	if subjectReference.Tag == "v1" {
		return &ocispecs.SubjectDescriptor{
			Descriptor: oci.Descriptor{
				Digest: subjectDigest,
			},
		}, nil
	}
	return &ocispecs.SubjectDescriptor{
		Descriptor: oci.Descriptor{
			Digest: subjectReference.Digest,
		},
	}, nil
}

type mockVerifier struct {
	canVerify      bool
	verifierResult verifier.VerifierResult
}

func (v *mockVerifier) Name() string {
	return "verifier-mockVerifier"
}

func (v *mockVerifier) Type() string {
	return "mockVerifier"
}

func (v *mockVerifier) CanVerify(_ context.Context, _ ocispecs.ReferenceDescriptor) bool {
	return v.canVerify
}

func (v *mockVerifier) Verify(_ context.Context,
	_ common.Reference,
	_ ocispecs.ReferenceDescriptor,
	_ referrerstore.ReferrerStore) (verifier.VerifierResult, error) {
	if reflect.DeepEqual(v.verifierResult, verifier.VerifierResult{}) {
		return verifier.VerifierResult{}, errors.New("no verifier result")
	}
	return v.verifierResult, nil
}

func (v *mockVerifier) GetNestedReferences() []string {
	return nil
}

func TestVerifySubjectInternal_ResolveSubjectDescriptor_Failed(t *testing.T) {
	executor := Executor{}

	verifyParameters := e.VerifyParameters{
		Subject: "localhost:5000/net-monitor:v1",
	}

	_, err := executor.verifySubjectInternal(context.Background(), verifyParameters)

	if err == nil {
		t.Fatal("expected subject parsing to fail")
	}
}

func TestVerifySubjectInternal_ResolveSubjectDescriptor_Success(t *testing.T) {
	testDigest := digest.FromString("test")
	store := &mocks.TestStore{
		References: []ocispecs.ReferenceDescriptor{},
		ResolveMap: map[string]digest.Digest{
			"v1": testDigest,
		},
	}

	executor := Executor{
		ReferrerStores: []referrerstore.ReferrerStore{store},
		PolicyEnforcer: &mockPolicyProvider{},
	}

	verifyParameters := e.VerifyParameters{
		Subject: "localhost:5000/net-monitor:v1",
	}

	if _, err := executor.verifySubjectInternal(context.Background(), verifyParameters); !errors.Is(err, ratifyerrors.ErrorCodeNoVerifierReport.WithDetail("")) {
		t.Fatalf("expected ErrReferrersNotFound actual %v", err)
	}
}

func TestVerifySubjectInternal_Verify_NoReferrers(t *testing.T) {
	testDigest := digest.FromString("test")
	configPolicy := policyConfig.PolicyEnforcer{}
	ex := &Executor{
		PolicyEnforcer: configPolicy,
		ReferrerStores: []referrerstore.ReferrerStore{&mocks.TestStore{
			ResolveMap: map[string]digest.Digest{
				"v1": testDigest,
			},
		}},
		Verifiers: []verifier.ReferenceVerifier{&TestVerifier{}},
		Config: &exConfig.ExecutorConfig{
			VerificationRequestTimeout: nil,
			MutationRequestTimeout:     nil,
		},
	}

	verifyParameters := e.VerifyParameters{
		Subject: "localhost:5000/net-monitor:v1",
	}

	if _, err := ex.verifySubjectInternal(context.Background(), verifyParameters); !errors.Is(err, ratifyerrors.ErrorCodeNoVerifierReport.WithDetail("")) {
		t.Fatalf("expected ErrReferrersNotFound actual %v", err)
	}
}

func TestVerifySubjectInternal_CanVerify_ExpectedResults(t *testing.T) {
	testDigest := digest.FromString("test")
	configPolicy := policyConfig.PolicyEnforcer{
		ArtifactTypePolicies: map[string]policyTypes.ArtifactTypeVerifyPolicy{
			testArtifactType1: policyTypes.AnyVerifySuccess,
		}}
	store := &mocks.TestStore{References: []ocispecs.ReferenceDescriptor{
		{
			ArtifactType: testArtifactType1,
		},
		{
			ArtifactType: "test-type2",
		}},
		ResolveMap: map[string]digest.Digest{
			"v1": testDigest,
		},
	}
	ver := &TestVerifier{
		CanVerifyFunc: func(at string) bool {
			return at == testArtifactType1
		},
		VerifyResult: func(_ string) bool {
			return true
		},
	}

	ex := &Executor{
		PolicyEnforcer: configPolicy,
		ReferrerStores: []referrerstore.ReferrerStore{store},
		Verifiers:      []verifier.ReferenceVerifier{ver},
		Config: &exConfig.ExecutorConfig{
			VerificationRequestTimeout: nil,
			MutationRequestTimeout:     nil,
		},
	}

	verifyParameters := e.VerifyParameters{
		Subject: "localhost:5000/net-monitor:v1",
	}

	result, err := ex.verifySubjectInternal(context.Background(), verifyParameters)

	if err != nil {
		t.Fatalf("verification failed with err %v", err)
	}

	if !result.IsSuccess {
		t.Fatal("verification expected to be success")
	}

	if len(result.VerifierReports) != 1 {
		t.Fatalf("verification expected to return single report but actual count %d", len(result.VerifierReports))
	}
}

func TestVerifySubjectInternal_VerifyFailures_ExpectedResults(t *testing.T) {
	testDigest := digest.FromString("test")
	testArtifactType := "test-type1"
	configPolicy := policyConfig.PolicyEnforcer{
		ArtifactTypePolicies: map[string]policyTypes.ArtifactTypeVerifyPolicy{
			testArtifactType: policyTypes.AnyVerifySuccess,
		}}
	store := &mocks.TestStore{References: []ocispecs.ReferenceDescriptor{
		{
			ArtifactType: testArtifactType,
		},
		{
			ArtifactType: "test-type2",
		}},
		ResolveMap: map[string]digest.Digest{
			"v1": testDigest,
		},
	}
	ver := &TestVerifier{
		CanVerifyFunc: func(_ string) bool {
			return true
		},
		VerifyResult: func(artifactType string) bool {
			return artifactType != testArtifactType
		},
	}

	ex := &Executor{
		PolicyEnforcer: configPolicy,
		ReferrerStores: []referrerstore.ReferrerStore{store},
		Verifiers:      []verifier.ReferenceVerifier{ver},
		Config: &exConfig.ExecutorConfig{
			VerificationRequestTimeout: nil,
			MutationRequestTimeout:     nil,
		},
	}

	verifyParameters := e.VerifyParameters{
		Subject: "localhost:5000/net-monitor:v1",
	}

	result, err := ex.verifySubjectInternal(context.Background(), verifyParameters)

	if err != nil {
		t.Fatalf("verification failed with err %v", err)
	}

	if result.IsSuccess {
		t.Fatal("verification expected to fail")
	}
}

func TestVerifySubjectInternal_VerifySuccess_ExpectedResults(t *testing.T) {
	testDigest := digest.FromString("test")
	configPolicy := policyConfig.PolicyEnforcer{
		ArtifactTypePolicies: map[string]policyTypes.ArtifactTypeVerifyPolicy{
			testArtifactType1: policyTypes.AnyVerifySuccess,
			testArtifactType2: policyTypes.AnyVerifySuccess,
		}}
	store := &mocks.TestStore{References: []ocispecs.ReferenceDescriptor{
		{
			ArtifactType: testArtifactType1,
		},
		{
			ArtifactType: testArtifactType2,
		}},
		ResolveMap: map[string]digest.Digest{
			"v1": testDigest,
		},
	}
	ver := &TestVerifier{
		CanVerifyFunc: func(_ string) bool {
			return true
		},
		VerifyResult: func(_ string) bool {
			return true
		},
	}

	ex := &Executor{
		PolicyEnforcer: configPolicy,
		ReferrerStores: []referrerstore.ReferrerStore{store},
		Verifiers:      []verifier.ReferenceVerifier{ver},
		Config: &exConfig.ExecutorConfig{
			VerificationRequestTimeout: nil,
			MutationRequestTimeout:     nil,
		},
	}

	verifyParameters := e.VerifyParameters{
		Subject: "localhost:5000/net-monitor:v1",
	}

	result, err := ex.verifySubjectInternal(context.Background(), verifyParameters)

	if err != nil {
		t.Fatalf("verification failed with err %v", err)
	}

	if !result.IsSuccess {
		t.Fatal("verification expected to fail")
	}

	if len(result.VerifierReports) != 2 {
		t.Fatalf("verification expected to return two reports but actual count %d", len(result.VerifierReports))
	}
}

// TestVerifySubjectInternalWithDecision_MultipleArtifacts_ExpectedResults tests multiple artifacts are verified concurrently
func TestVerifySubjectInternalWithDecision_MultipleArtifacts_ExpectedResults(t *testing.T) {
	testDigest := digest.FromString("test")
	configPolicy := policyConfig.PolicyEnforcer{
		ArtifactTypePolicies: map[string]policyTypes.ArtifactTypeVerifyPolicy{
			testArtifactType1: policyTypes.AnyVerifySuccess,
			testArtifactType2: policyTypes.AnyVerifySuccess,
		}}
	store := &mocks.TestStore{References: []ocispecs.ReferenceDescriptor{
		{
			ArtifactType: testArtifactType1,
		},
		{
			ArtifactType: testArtifactType2,
		}},
		ResolveMap: map[string]digest.Digest{
			"v1": testDigest,
		},
	}
	ver := &TestVerifier{
		CanVerifyFunc: func(_ string) bool {
			return true
		},
		VerifyResult: func(artifactType string) bool {
			if artifactType == testArtifactType1 {
				time.Sleep(2 * time.Second)
			}
			return true
		},
	}

	ex := &Executor{
		PolicyEnforcer: configPolicy,
		ReferrerStores: []referrerstore.ReferrerStore{store},
		Verifiers:      []verifier.ReferenceVerifier{ver},
		Config: &exConfig.ExecutorConfig{
			VerificationRequestTimeout: nil,
			MutationRequestTimeout:     nil,
		},
	}

	verifyParameters := e.VerifyParameters{
		Subject: "localhost:5000/net-monitor:v1",
	}

	result, err := ex.verifySubjectInternal(context.Background(), verifyParameters)

	if err != nil {
		t.Fatalf("verification failed with err %v", err)
	}

	if !result.IsSuccess {
		t.Fatal("verification expected to fail")
	}

	if len(result.VerifierReports) != 2 {
		t.Fatalf("verification expected to return two reports but actual count %d", len(result.VerifierReports))
	}

	if result.VerifierReports[0].(verifier.VerifierResult).ArtifactType != "test-type2" {
		t.Fatalf("verification expected to return second artifact verifier report first")
	}
}

// TestVerifySubjectInternal_NestedReferences_Expected tests verifier config can specify nested references
func TestVerifySubjectInternal_NestedReferences_Expected(t *testing.T) {
	configPolicy := policyConfig.PolicyEnforcer{
		ArtifactTypePolicies: map[string]policyTypes.ArtifactTypeVerifyPolicy{
			"default": "all",
		}}

	store := mocks.CreateNewTestStoreForNestedSbom()

	// sbom verifier WITH nested references in config
	sbomVerifier := &TestVerifier{
		CanVerifyFunc: func(at string) bool {
			return at == mocks.SbomArtifactType
		},
		VerifyResult: func(_ string) bool {
			return true
		},
		nestedReferences: []string{"string-content-does-not-matter"},
	}

	signatureVerifier := &TestVerifier{
		CanVerifyFunc: func(at string) bool {
			return at == mocks.SignatureArtifactType
		},
		VerifyResult: func(_ string) bool {
			return true
		},
	}

	ex := &Executor{
		PolicyEnforcer: configPolicy,
		ReferrerStores: []referrerstore.ReferrerStore{store},
		Verifiers:      []verifier.ReferenceVerifier{sbomVerifier, signatureVerifier},
		Config: &exConfig.ExecutorConfig{
			VerificationRequestTimeout: nil,
			MutationRequestTimeout:     nil,
		},
	}

	verifyParameters := e.VerifyParameters{
		Subject: mocks.TestSubjectWithDigest,
	}

	result, err := ex.verifySubjectInternal(context.Background(), verifyParameters)

	if err != nil {
		t.Fatalf("verification failed with err %v", err)
	}

	if !result.IsSuccess {
		t.Fatal("verification expected to succeed")
	}

	if len(result.VerifierReports) != 2 {
		t.Fatalf("verification expected to return two reports but actual count %d", len(result.VerifierReports))
	}

	for _, report := range result.VerifierReports {
		castedReport := report.(verifier.VerifierResult)

		// check sbom report
		if castedReport.ArtifactType == mocks.SbomArtifactType {
			// check sbom has one nested results
			if len(castedReport.NestedResults) != 1 {
				t.Fatalf("Expected sbom report to have 1 nested result")
			}
			// check sbom nested result is successful
			if !castedReport.NestedResults[0].IsSuccess {
				t.Fatalf("Expected the sbom nested result to be successful")
			}
		} else {
			// check non-sbom reports have zero nested results
			if len(castedReport.NestedResults) != 0 {
				t.Fatalf("Expected non-sboms reports to have zero nested results")
			}
		}
	}
}

// TestVerifySubjectInternal__NoNestedReferences_Expected tests verifier config can specify no nested references
func TestVerifySubjectInternal_NoNestedReferences_Expected(t *testing.T) {
	configPolicy := policyConfig.PolicyEnforcer{
		ArtifactTypePolicies: map[string]policyTypes.ArtifactTypeVerifyPolicy{
			"default": "all",
		}}
	store := mocks.CreateNewTestStoreForNestedSbom()

	// sbom verifier WITHOUT nested references in config
	sbomVer := &TestVerifier{
		CanVerifyFunc: func(at string) bool {
			return at == mocks.SbomArtifactType
		},
		VerifyResult: func(_ string) bool {
			return true
		},
	}

	signatureVer := &TestVerifier{
		CanVerifyFunc: func(at string) bool {
			return at == mocks.SignatureArtifactType
		},
		VerifyResult: func(_ string) bool {
			return true
		},
	}

	ex := &Executor{
		PolicyEnforcer: configPolicy,
		ReferrerStores: []referrerstore.ReferrerStore{store},
		Verifiers:      []verifier.ReferenceVerifier{sbomVer, signatureVer},
		Config: &exConfig.ExecutorConfig{
			VerificationRequestTimeout: nil,
			MutationRequestTimeout:     nil,
		},
	}

	verifyParameters := e.VerifyParameters{
		Subject: mocks.TestSubjectWithDigest,
	}

	result, err := ex.verifySubjectInternal(context.Background(), verifyParameters)

	if err != nil {
		t.Fatalf("verification failed with err %v", err)
	}

	if !result.IsSuccess {
		t.Fatal("verification expected to succeed")
	}

	if len(result.VerifierReports) != 2 {
		t.Fatalf("verification expected to return two reports but actual count %d", len(result.VerifierReports))
	}

	// check each report for: success, zero nested results
	for _, report := range result.VerifierReports {
		castedReport := report.(verifier.VerifierResult)

		// check for success
		if !castedReport.IsSuccess {
			t.Fatal("verification expected to succeed")
		}
		// check there are no nested results
		if len(castedReport.NestedResults) != 0 {
			t.Fatalf("expected reports to have zero nested results")
		}
	}
}

// TestGetVerifyRequestTimeout_ExpectedResults tests the verification request timeout returned
func TestGetVerifyRequestTimeout_ExpectedResults(t *testing.T) {
	testcases := []struct {
		setTimeout      int
		ex              Executor
		expectedTimeout int
	}{
		{
			setTimeout: -1,
			ex: Executor{
				PolicyEnforcer: policyConfig.PolicyEnforcer{},
				ReferrerStores: []referrerstore.ReferrerStore{},
				Verifiers:      []verifier.ReferenceVerifier{},
				Config:         nil,
			},
			expectedTimeout: 2900,
		},
		{
			setTimeout: -1,
			ex: Executor{
				PolicyEnforcer: policyConfig.PolicyEnforcer{},
				ReferrerStores: []referrerstore.ReferrerStore{},
				Verifiers:      []verifier.ReferenceVerifier{},
				Config: &exConfig.ExecutorConfig{
					VerificationRequestTimeout: nil,
					MutationRequestTimeout:     nil,
				},
			},
			expectedTimeout: 2900,
		},
		{
			setTimeout: 5000,
			ex: Executor{
				PolicyEnforcer: policyConfig.PolicyEnforcer{},
				ReferrerStores: []referrerstore.ReferrerStore{},
				Verifiers:      []verifier.ReferenceVerifier{},
				Config: &exConfig.ExecutorConfig{
					VerificationRequestTimeout: new(int),
					MutationRequestTimeout:     nil,
				},
			},
			expectedTimeout: 5000,
		},
	}

	for _, testcase := range testcases {
		if testcase.setTimeout >= 0 {
			*testcase.ex.Config.VerificationRequestTimeout = testcase.setTimeout
		}
		expected := time.Millisecond * time.Duration(testcase.expectedTimeout)
		actual := testcase.ex.GetVerifyRequestTimeout()
		if actual != expected {
			t.Fatalf("verification request timeout returned expected %dms but got %dms", expected.Milliseconds(), actual.Milliseconds())
		}
	}
}

// TestGetMutationRequestTimeout_ExpectedResults tests the mutation request timeout returned
func TestGetMutationRequestTimeout_ExpectedResults(t *testing.T) {
	testcases := []struct {
		setTimeout      int
		ex              Executor
		expectedTimeout int
	}{
		{
			setTimeout: -1,
			ex: Executor{
				PolicyEnforcer: policyConfig.PolicyEnforcer{},
				ReferrerStores: []referrerstore.ReferrerStore{},
				Verifiers:      []verifier.ReferenceVerifier{},
				Config:         nil,
			},
			expectedTimeout: 950,
		},
		{
			setTimeout: -1,
			ex: Executor{
				PolicyEnforcer: policyConfig.PolicyEnforcer{},
				ReferrerStores: []referrerstore.ReferrerStore{},
				Verifiers:      []verifier.ReferenceVerifier{},
				Config: &exConfig.ExecutorConfig{
					VerificationRequestTimeout: nil,
					MutationRequestTimeout:     nil,
				},
			},
			expectedTimeout: 950,
		},
		{
			setTimeout: 2400,
			ex: Executor{
				PolicyEnforcer: policyConfig.PolicyEnforcer{},
				ReferrerStores: []referrerstore.ReferrerStore{},
				Verifiers:      []verifier.ReferenceVerifier{},
				Config: &exConfig.ExecutorConfig{
					VerificationRequestTimeout: nil,
					MutationRequestTimeout:     new(int),
				},
			},
			expectedTimeout: 2400,
		},
	}

	for _, testcase := range testcases {
		if testcase.setTimeout >= 0 {
			*testcase.ex.Config.MutationRequestTimeout = testcase.setTimeout
		}
		expected := time.Millisecond * time.Duration(testcase.expectedTimeout)
		actual := testcase.ex.GetMutationRequestTimeout()
		if actual != expected {
			t.Fatalf("mutation request timeout returned expected %dms but got %dms", expected.Milliseconds(), actual.Milliseconds())
		}
	}
}

func TestVerifySubject(t *testing.T) {
	testCases := []struct {
		name           string
		params         e.VerifyParameters
		expectedResult types.VerifyResult
		stores         []referrerstore.ReferrerStore
		policyEnforcer policyprovider.PolicyProvider
		verifiers      []verifier.ReferenceVerifier
		referrers      []ocispecs.ReferenceDescriptor
		expectErr      bool
	}{
		{
			name: "verify subject with invalid subject",
			policyEnforcer: &mockPolicyProvider{
				policyType: pt.RegoPolicy,
			},
			params:    e.VerifyParameters{},
			expectErr: true,
		},
		{
			name: "error from ListReferrers",
			params: e.VerifyParameters{
				Subject: subject1,
			},
			stores: []referrerstore.ReferrerStore{
				&mockStore{
					referrers: nil,
				},
			},
			policyEnforcer: &mockPolicyProvider{
				policyType: pt.RegoPolicy,
			},
			expectErr:      true,
			expectedResult: types.VerifyResult{},
		},
		{
			name: "empty referrers",
			params: e.VerifyParameters{
				Subject: subject1,
			},
			stores: []referrerstore.ReferrerStore{
				&mockStore{
					referrers: nil,
				},
			},
			policyEnforcer: &mockPolicyProvider{
				policyType: pt.RegoPolicy,
			},
			expectErr:      true,
			expectedResult: types.VerifyResult{},
		},
		{
			name: "one signature without matching verifier",
			params: e.VerifyParameters{
				Subject: subject1,
			},
			stores: []referrerstore.ReferrerStore{
				&mockStore{
					referrers: map[string][]ocispecs.ReferenceDescriptor{
						subjectDigest: {
							{
								ArtifactType: artifactType,
								Descriptor: oci.Descriptor{
									Digest: signatureDigest,
								},
							},
						},
					},
				},
			},
			verifiers: []verifier.ReferenceVerifier{
				&mockVerifier{
					canVerify: false,
				},
			},
			policyEnforcer: &mockPolicyProvider{
				result:     true,
				policyType: pt.RegoPolicy,
			},
			expectErr: false,
			expectedResult: types.VerifyResult{
				IsSuccess: true,
			},
		},
		{
			name: "one signature with verifier failed",
			params: e.VerifyParameters{
				Subject: subject1,
			},
			stores: []referrerstore.ReferrerStore{
				&mockStore{
					referrers: map[string][]ocispecs.ReferenceDescriptor{
						subjectDigest: {
							{
								ArtifactType: artifactType,
								Descriptor: oci.Descriptor{
									Digest: signatureDigest,
								},
							},
						},
					},
				},
			},
			verifiers: []verifier.ReferenceVerifier{
				&mockVerifier{
					canVerify: true,
					verifierResult: verifier.VerifierResult{
						IsSuccess: false,
					},
				},
			},
			policyEnforcer: &mockPolicyProvider{
				result:     false,
				policyType: pt.RegoPolicy,
			},
			expectErr:      false,
			expectedResult: types.VerifyResult{IsSuccess: false},
		},
		{
			name: "one signature with verifier success",
			params: e.VerifyParameters{
				Subject: subject1,
			},
			stores: []referrerstore.ReferrerStore{
				&mockStore{
					referrers: map[string][]ocispecs.ReferenceDescriptor{
						subjectDigest: {
							{
								ArtifactType: artifactType,
								Descriptor: oci.Descriptor{
									Digest: signatureDigest,
								},
							},
						},
					},
				},
			},
			verifiers: []verifier.ReferenceVerifier{
				&mockVerifier{
					canVerify: true,
					verifierResult: verifier.VerifierResult{
						IsSuccess: true,
					},
				},
			},
			policyEnforcer: &mockPolicyProvider{
				result:     true,
				policyType: pt.RegoPolicy,
			},
			expectErr: false,
			expectedResult: types.VerifyResult{
				IsSuccess: true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ex := &Executor{tc.stores, tc.policyEnforcer, tc.verifiers, nil}

			result, err := ex.VerifySubject(context.Background(), tc.params)
			if (err != nil) != tc.expectErr {
				t.Fatalf("expected error %v but got %v", tc.expectErr, err)
			}
			if result.IsSuccess != tc.expectedResult.IsSuccess {
				t.Fatalf("expected result: %+v but got: %+v", tc.expectedResult, result)
			}
		})
	}
}
