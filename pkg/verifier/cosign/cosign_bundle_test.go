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

package cosign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/opencontainers/go-digest"
	imgspec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/ratify-project/ratify/pkg/common"
	"github.com/ratify-project/ratify/pkg/keymanagementprovider"
	"github.com/ratify-project/ratify/pkg/ocispecs"
	"github.com/ratify-project/ratify/pkg/referrerstore/mocks"
	"github.com/ratify-project/ratify/pkg/verifier/config"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	testBundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"
	testInTotoType      = "application/vnd.in-toto+json"
	testSignPredicate   = "https://sigstore.dev/cosign/sign/v1"
)

// createTestBundle creates a v0.3 Sigstore bundle with a DSSE envelope over an in-toto
// statement whose subject is subjectHex. If cert is nil, a public key hint is used.
func createTestBundle(t *testing.T, signer crypto.Signer, cert *x509.Certificate, subjectHex string) []byte {
	t.Helper()
	statement := fmt.Sprintf(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"test","digest":{"sha256":"%s"}}],"predicateType":"%s","predicate":{}}`, subjectHex, testSignPredicate)
	pae := fmt.Sprintf("DSSEv1 %d %s %d %s", len(testInTotoType), testInTotoType, len(statement), statement)
	h := sha256.Sum256([]byte(pae))
	sig, err := signer.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	vm := &protobundle.VerificationMaterial{}
	if cert != nil {
		vm.Content = &protobundle.VerificationMaterial_Certificate{Certificate: &protocommon.X509Certificate{RawBytes: cert.Raw}}
	} else {
		vm.Content = &protobundle.VerificationMaterial_PublicKey{PublicKey: &protocommon.PublicKeyIdentifier{Hint: "test"}}
	}
	pb := &protobundle.Bundle{
		MediaType:            testBundleMediaType,
		VerificationMaterial: vm,
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: &protodsse.Envelope{
			Payload:     []byte(statement),
			PayloadType: testInTotoType,
			Signatures:  []*protodsse.Signature{{Sig: sig}},
		}},
	}
	b, err := protojson.Marshal(pb)
	if err != nil {
		t.Fatalf("failed to marshal bundle: %v", err)
	}
	return b
}

func newTestSubjectHash(t *testing.T) v1.Hash {
	t.Helper()
	sum := sha256.Sum256([]byte("subject"))
	return v1.Hash{Algorithm: "sha256", Hex: hex.EncodeToString(sum[:])}
}

func TestIsSigstoreBundle(t *testing.T) {
	if !isSigstoreBundle(imgspec.Descriptor{MediaType: testBundleMediaType}) {
		t.Errorf("expected bundle media type to be detected")
	}
	if isSigstoreBundle(imgspec.Descriptor{MediaType: "application/vnd.dev.cosign.simplesigning.v1+json"}) {
		t.Errorf("expected simplesigning media type to not be detected as a bundle")
	}
}

func TestParseSigstoreBundle(t *testing.T) {
	if _, err := parseSigstoreBundle([]byte("not json")); err == nil {
		t.Errorf("expected error for invalid bundle")
	}
	if _, err := parseSigstoreBundle([]byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`)); err == nil {
		t.Errorf("expected error for incomplete bundle")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, err := parseSigstoreBundle(createTestBundle(t, key, nil, newTestSubjectHash(t).Hex))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if onlyV2, err := hasOnlyRekorV2Entries(b); err != nil || onlyV2 {
		t.Errorf("expected bundle without tlog entries to not be Rekor v2 only, got %v, %v", onlyV2, err)
	}
}

func TestVerifyBundle_Key(t *testing.T) {
	subjectHash := newTestSubjectHash(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherSum := sha256.Sum256([]byte("other"))
	validBundle := createTestBundle(t, key, nil, subjectHash.Hex)
	keyOpts := cosign.CheckOpts{IgnoreTlog: true}

	tc := []struct {
		name        string
		keys        map[PKKey]keymanagementprovider.PublicKey
		bundle      []byte
		expectValid bool
		expectErr   bool
	}{
		{
			name:        "valid signature",
			keys:        map[PKKey]keymanagementprovider.PublicKey{{Provider: "test"}: {Key: key.Public(), ProviderType: "inline"}},
			bundle:      validBundle,
			expectValid: true,
		},
		{
			name:   "wrong key",
			keys:   map[PKKey]keymanagementprovider.PublicKey{{Provider: "test"}: {Key: otherKey.Public(), ProviderType: "inline"}},
			bundle: validBundle,
		},
		{
			name:   "subject digest mismatch",
			keys:   map[PKKey]keymanagementprovider.PublicKey{{Provider: "test"}: {Key: key.Public(), ProviderType: "inline"}},
			bundle: createTestBundle(t, key, nil, hex.EncodeToString(otherSum[:])),
		},
		{
			name:        "one of multiple keys valid",
			keys:        map[PKKey]keymanagementprovider.PublicKey{{Provider: "a"}: {Key: otherKey.Public(), ProviderType: "inline"}, {Provider: "b"}: {Key: key.Public(), ProviderType: "inline"}},
			bundle:      validBundle,
			expectValid: true,
		},
		{
			name:      "invalid bundle",
			keys:      map[PKKey]keymanagementprovider.PublicKey{{Provider: "test"}: {Key: key.Public(), ProviderType: "inline"}},
			bundle:    []byte("invalid"),
			expectErr: true,
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			verifications, valid, err := verifyBundle(context.Background(), tt.keys, tt.bundle, keyOpts, subjectHash)
			if (err != nil) != tt.expectErr {
				t.Fatalf("verifyBundle() error = %v, expectErr %v", err, tt.expectErr)
			}
			if valid != tt.expectValid {
				t.Fatalf("verifyBundle() valid = %v, want %v, verifications: %+v", valid, tt.expectValid, verifications)
			}
			if !tt.expectErr && len(verifications) != len(tt.keys) {
				t.Fatalf("expected %d verifications, got %d", len(tt.keys), len(verifications))
			}
			for _, v := range verifications {
				if v.IsSuccess && v.BundleVerified {
					t.Errorf("expected BundleVerified to be false when tlog is ignored")
				}
				if !v.IsSuccess && v.Err == "" {
					t.Errorf("expected error message for failed verification")
				}
			}
		})
	}
}

func TestVerifyBundle_Keyless(t *testing.T) {
	subjectHash := newTestSubjectHash(t)
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("failed to create virtual sigstore: %v", err)
	}
	leaf, leafKey, err := vs.GenerateLeafCert(testIdentity, testIssuer)
	if err != nil {
		t.Fatalf("failed to generate leaf cert: %v", err)
	}
	signer, ok := leafKey.(crypto.Signer)
	if !ok {
		t.Fatalf("leaf key is not a signer")
	}
	bundleBytes := createTestBundle(t, signer, leaf, subjectHash.Hex)

	defer func() { getTrustedRoot = getTrustedRootDefault }()

	tc := []struct {
		name        string
		identity    string
		rootErr     bool
		expectValid bool
		expectErr   bool
	}{
		{name: "valid identity", identity: testIdentity, expectValid: true},
		{name: "wrong identity", identity: "someone@else.com"},
		{name: "trusted root error", identity: testIdentity, rootErr: true, expectErr: true},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			getTrustedRoot = func() (root.TrustedMaterial, error) {
				if tt.rootErr {
					return nil, fmt.Errorf("tuf error")
				}
				return vs, nil
			}
			co := cosign.CheckOpts{
				IgnoreTlog: true,
				IgnoreSCT:  true,
				Identities: []cosign.Identity{{Subject: tt.identity, Issuer: testIssuer}},
			}
			verifications, valid, err := verifyBundle(context.Background(), nil, bundleBytes, co, subjectHash)
			if (err != nil) != tt.expectErr {
				t.Fatalf("verifyBundle() error = %v, expectErr %v", err, tt.expectErr)
			}
			if valid != tt.expectValid {
				t.Fatalf("verifyBundle() valid = %v, want %v, verifications: %+v", valid, tt.expectValid, verifications)
			}
			if tt.expectValid && (len(verifications) != 1 || verifications[0].Summary[len(verifications[0].Summary)-1] != certVerifierMessage) {
				t.Errorf("unexpected verifications: %+v", verifications)
			}
		})
	}
}

func TestVerifyInternal_Bundle(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	subjectHash := newTestSubjectHash(t)
	subjectDigest := digest.Digest("sha256:" + subjectHash.Hex)
	bundleBytes := createTestBundle(t, key, nil, subjectHash.Hex)
	bundleDigest := digest.FromBytes(bundleBytes)
	refDigest := digest.FromString("ref")

	subjectRef := common.Reference{Digest: subjectDigest, Original: ratifySampleImageRef}
	refDescriptor := ocispecs.ReferenceDescriptor{
		ArtifactType: testBundleMediaType,
		Descriptor:   imgspec.Descriptor{Digest: refDigest, MediaType: imgspec.MediaTypeImageManifest},
	}
	store := &mocks.MemoryTestStore{
		Manifests: map[digest.Digest]ocispecs.ReferenceManifest{
			refDigest: {
				MediaType: imgspec.MediaTypeImageManifest,
				Blobs:     []imgspec.Descriptor{{Digest: bundleDigest, MediaType: testBundleMediaType}},
			},
		},
		Subjects: map[digest.Digest]*ocispecs.SubjectDescriptor{
			subjectDigest: {Descriptor: imgspec.Descriptor{Digest: subjectDigest, MediaType: imgspec.MediaTypeImageManifest}},
		},
		Blobs: map[digest.Digest][]byte{bundleDigest: bundleBytes},
	}

	defer func() { getKeyMapOpts = getKeyMapOptsDefault }()

	tc := []struct {
		name          string
		key           crypto.PublicKey
		expectSuccess bool
	}{
		{name: "valid bundle signature", key: key.Public(), expectSuccess: true},
		{name: "invalid bundle signature", key: func() crypto.PublicKey { k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); return k.Public() }()},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			getKeyMapOpts = func(_ context.Context, _ TrustPolicy, _ string) (map[PKKey]keymanagementprovider.PublicKey, cosign.CheckOpts, error) {
				return map[PKKey]keymanagementprovider.PublicKey{{Provider: "test"}: {Key: tt.key, ProviderType: "inline"}}, cosign.CheckOpts{IgnoreTlog: true}, nil
			}
			v, err := (&cosignVerifierFactory{}).Create("", config.VerifierConfig{
				"name":          "test",
				"artifactTypes": testBundleMediaType,
				"type":          "cosign",
				"trustPolicies": []TrustPolicyConfig{{Name: "test-policy", Keys: []KeyConfig{{Provider: "test"}}, Scopes: []string{"*"}}},
			}, "", "test-namespace")
			if err != nil {
				t.Fatalf("Create() error = %v", err)
			}
			if !v.CanVerify(context.Background(), refDescriptor) {
				t.Fatalf("expected verifier to support bundle artifact type")
			}
			result, _ := v.Verify(context.Background(), subjectRef, refDescriptor, store)
			if result.IsSuccess != tt.expectSuccess {
				t.Fatalf("IsSuccess = %v, want %v, result: %+v", result.IsSuccess, tt.expectSuccess, result)
			}
			ext, ok := result.Extensions.(Extension)
			if !ok || len(ext.SignatureExtension) != 1 || ext.SignatureExtension[0].Signature != bundleDigest.String() {
				t.Fatalf("unexpected extensions: %+v", result.Extensions)
			}
		})
	}
}

func TestVerifyLegacy_BundleNotSupported(t *testing.T) {
	refDigest := digest.FromString("ref")
	subjectDigest := digest.FromString("subject")
	store := &mocks.MemoryTestStore{
		Manifests: map[digest.Digest]ocispecs.ReferenceManifest{
			refDigest: {
				MediaType: imgspec.MediaTypeImageManifest,
				Blobs:     []imgspec.Descriptor{{Digest: digest.FromString("bundle"), MediaType: testBundleMediaType}},
			},
		},
		Subjects: map[digest.Digest]*ocispecs.SubjectDescriptor{
			subjectDigest: {Descriptor: imgspec.Descriptor{Digest: subjectDigest, MediaType: imgspec.MediaTypeImageManifest}},
		},
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pemBytes, err := cryptoutils.MarshalPublicKeyToPEM(key.Public())
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "cosign.pub")
	if err := os.WriteFile(keyPath, pemBytes, 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}
	v := &cosignVerifier{name: "test", verifierType: "cosign", isLegacy: true, config: &PluginConfig{KeyRef: keyPath}}
	result, _ := v.verifyLegacy(context.Background(), common.Reference{Digest: subjectDigest, Original: ratifySampleImageRef},
		ocispecs.ReferenceDescriptor{Descriptor: imgspec.Descriptor{Digest: refDigest, MediaType: imgspec.MediaTypeImageManifest}}, store)
	if result.IsSuccess || !strings.Contains(result.ErrorReason, "trustPolicies") {
		t.Fatalf("expected legacy bundle failure, got: %+v", result)
	}
}

func TestKeyHashType(t *testing.T) {
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if h, err := keyHashType(p384.Public()); err != nil || h != crypto.SHA384 {
		t.Errorf("expected SHA384, got %v, %v", h, err)
	}
	if _, err := keyHashType("invalid"); err == nil {
		t.Errorf("expected error for unsupported key type")
	}
}
