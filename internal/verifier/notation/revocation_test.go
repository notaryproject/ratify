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

package notation

import (
	"context"
	"crypto/x509"
	"testing"

	corecrl "github.com/notaryproject/notation-core-go/revocation/crl"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	"github.com/notaryproject/ratify-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type mockTrustStore struct{}

func (m *mockTrustStore) GetCertificates(context.Context, truststore.Type, string) ([]*x509.Certificate, error) {
	return nil, nil
}

func TestCreateCRLFetcher(t *testing.T) {
	t.Run("without cache", func(t *testing.T) {
		fetcher, err := createCRLFetcher(false)
		if err != nil {
			t.Fatalf("expected CRL fetcher: %v", err)
		}
		httpFetcher, ok := fetcher.(*corecrl.HTTPFetcher)
		if !ok {
			t.Fatalf("expected HTTP fetcher, got %T", fetcher)
		}
		if httpFetcher.Cache != nil {
			t.Fatal("expected CRL cache to be disabled")
		}
	})

	t.Run("with cache", func(t *testing.T) {
		oldCacheDir := dir.UserCacheDir
		dir.UserCacheDir = t.TempDir()
		t.Cleanup(func() {
			dir.UserCacheDir = oldCacheDir
		})

		fetcher, err := createCRLFetcher(true)
		if err != nil {
			t.Fatalf("expected CRL fetcher with cache: %v", err)
		}
		httpFetcher, ok := fetcher.(*corecrl.HTTPFetcher)
		if !ok {
			t.Fatalf("expected HTTP fetcher, got %T", fetcher)
		}
		if httpFetcher.Cache == nil {
			t.Fatal("expected CRL cache to be enabled")
		}
	})
}

func TestNewNotationVerifier(t *testing.T) {
	verifier, err := newNotationVerifier(&notationVerifierOptions{
		Name:           testName,
		TrustPolicyDoc: testTrustPolicyDocument(),
		TrustStore:     &mockTrustStore{},
		CRL: crlOptions{
			Cache: crlCacheOptions{Enabled: false},
		},
	})
	if err != nil {
		t.Fatalf("expected notation verifier with CRL validators: %v", err)
	}
	if _, ok := interface{}(verifier).(ratify.Verifier); !ok {
		t.Fatal("expected verifier to implement ratify.Verifier")
	}
	if verifier.Name() != testName {
		t.Fatalf("expected verifier name %q, got %q", testName, verifier.Name())
	}
	if verifier.Type() != verifierTypeNotation {
		t.Fatalf("expected verifier type %q, got %q", verifierTypeNotation, verifier.Type())
	}
	if !verifier.Verifiable(ocispec.Descriptor{
		ArtifactType: "application/vnd.cncf.notary.signature",
		MediaType:    ocispec.MediaTypeImageManifest,
	}) {
		t.Fatal("expected notation signature artifact to be verifiable")
	}
	if verifier.Verifiable(ocispec.Descriptor{
		ArtifactType: "application/example",
		MediaType:    ocispec.MediaTypeImageManifest,
	}) {
		t.Fatal("expected non-notation artifact to be unverifiable")
	}
}

func testTrustPolicyDocument() *trustpolicy.Document {
	return &trustpolicy.Document{
		Version: "1.0",
		TrustPolicies: []trustpolicy.TrustPolicy{
			{
				Name:           "default",
				RegistryScopes: []string{"*"},
				SignatureVerification: trustpolicy.SignatureVerification{
					VerificationLevel: "strict",
				},
				TrustStores:       []string{"ca:ratify"},
				TrustedIdentities: []string{"*"},
			},
		},
	}
}
