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
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/notaryproject/ratify/v2/internal/logger"
	"github.com/notaryproject/ratify/v2/pkg/common"
	"github.com/notaryproject/ratify/v2/pkg/keymanagementprovider"
	"github.com/notaryproject/ratify/v2/pkg/keymanagementprovider/azurekeyvault"
	"github.com/notaryproject/ratify/v2/pkg/ocispecs"
	"github.com/notaryproject/ratify/v2/pkg/referrerstore"
	"github.com/notaryproject/ratify/v2/pkg/utils"
	"github.com/notaryproject/ratify/v2/pkg/verifier"
	"github.com/notaryproject/ratify/v2/pkg/verifier/config"
	"github.com/notaryproject/ratify/v2/pkg/verifier/factory"
	"github.com/notaryproject/ratify/v2/pkg/verifier/types"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	re "github.com/notaryproject/ratify/v2/errors"
	"github.com/opencontainers/go-digest"
	imgspec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/sigstore/pkg/signature"
)

type PluginConfig struct {
	Name             string              `json:"name"`
	Type             string              `json:"type,omitempty"`
	ArtifactTypes    string              `json:"artifactTypes"`
	KeyRef           string              `json:"key,omitempty"`
	RekorURL         string              `json:"rekorURL,omitempty"`
	NestedReferences []string            `json:"nestedArtifactTypes,omitempty"`
	TrustPolicies    []TrustPolicyConfig `json:"trustPolicies,omitempty"`
}

// LegacyExtension is the structure for the verifier result extensions
// used for backwards compatibility with the legacy cosign verifier
type LegacyExtension struct {
	SignatureExtension []cosignExtension `json:"signatures,omitempty"`
}

// Extension is the structure for the verifier result extensions
// contains a list of signature verification results
// where each entry corresponds to a single signature verified
type Extension struct {
	SignatureExtension []cosignExtensionList `json:"signatures,omitempty"`
	TrustPolicy        string                `json:"trustPolicy,omitempty"`
}

// cosignExtensionList is the structure verifications performed
// per signature found in the image manifest
type cosignExtensionList struct {
	Signature     string            `json:"signature"`
	Verifications []cosignExtension `json:"verifications"`
}

// cosignExtension is the structure for the verification result
// of a single signature found in the image manifest for a
// single public key
type cosignExtension struct {
	SignatureDigest digest.Digest `json:"signatureDigest,omitempty"`
	IsSuccess       bool          `json:"isSuccess"`
	BundleVerified  bool          `json:"bundleVerified"`
	Err             string        `json:"error,omitempty"`
	KeyInformation  PKKey         `json:"keyInformation,omitempty"`
	Summary         []string      `json:"summary,omitempty"`
}

type cosignVerifier struct {
	name             string
	verifierType     string
	artifactTypes    []string
	nestedReferences []string
	config           *PluginConfig
	isLegacy         bool
	trustPolicies    *TrustPolicies
	namespace        string
}

type cosignVerifierFactory struct{}

var logOpt = logger.Option{
	ComponentType: logger.Verifier,
}

// used for mocking purposes
var getKeyMapOpts = getKeyMapOptsDefault

const (
	verifierType string = "cosign"
	// messages for verificationPerformedMessage. source: https://github.com/sigstore/cosign/blob/d275a272ec0cdf5a4c22d01b891a4d7e20164d71/cmd/cosign/cli/verify/verify.go#L318
	annotationMessage    string = "The specified annotations were verified."                                                    // TODO: check if message has been updated by upstream cosign cli
	claimsMessage        string = "The cosign claims were validated."                                                           // TODO: check if message has been updated by upstream cosign cli
	offlineBundleMessage string = "Existence of the claims in the transparency log was verified offline."                       // TODO: check if message has been updated by upstream cosign cli
	rekorClaimsMessage   string = "The claims were present in the transparency log."                                            // TODO: check if message has been updated by upstream cosign cli
	rekorSigMessage      string = "The signatures were integrated into the transparency log when the certificate was valid."    // TODO: check if message has been updated by upstream cosign cli
	sigVerifierMessage   string = "The signatures were verified against the specified public key."                              // TODO: check if message has been updated by upstream cosign cli
	certVerifierMessage  string = "The code-signing certificate was verified using trusted certificate authority certificates." // TODO: check if message has been updated by upstream cosign cli
)

// init() registers the cosign verifier with the factory
func init() {
	factory.Register(verifierType, &cosignVerifierFactory{})
}

// Create creates a new cosign verifier
func (f *cosignVerifierFactory) Create(_ string, verifierConfig config.VerifierConfig, _ string, namespace string) (verifier.ReferenceVerifier, error) {
	logger.GetLogger(context.Background(), logOpt).Debugf("creating cosign verifier with config %v, namespace '%v'", verifierConfig, namespace)
	verifierName, hasName := verifierConfig[types.Name].(string)
	if !hasName {
		return nil, re.ErrorCodeConfigInvalid.WithDetail("The name field is required in the Cosign Verifier configuration")
	}

	config, err := parseVerifierConfig(verifierConfig)
	if err != nil {
		return nil, re.ErrorCodeConfigInvalid.WithDetail("Failed to create the Cosign Verifier").WithError(err)
	}

	// if key or rekorURL is provided, trustPolicies should not be provided
	if (config.KeyRef != "" || config.RekorURL != "") && len(config.TrustPolicies) > 0 {
		return nil, re.ErrorCodeConfigInvalid.WithDetail("'key' and 'rekorURL' are part of Cosign legacy configuration and cannot be used with `trustPolicies` parameter")
	}

	var trustPolicies *TrustPolicies
	legacy := true
	// if trustPolicies are provided and non-legacy, create the trust policies
	if config.KeyRef == "" && config.RekorURL == "" && len(config.TrustPolicies) > 0 {
		logger.GetLogger(context.Background(), logOpt).Debugf("legacy cosign verifier configuration not found, creating trust policies")
		trustPolicies, err = CreateTrustPolicies(config.TrustPolicies, verifierName)
		if err != nil {
			return nil, re.ErrorCodePluginInitFailure.WithDetail("Failed to create the Cosign Verifier").WithError(err)
		}
		legacy = false
	}

	return &cosignVerifier{
		name:             verifierName,
		verifierType:     config.Type,
		artifactTypes:    strings.Split(config.ArtifactTypes, ","),
		nestedReferences: config.NestedReferences,
		config:           config,
		isLegacy:         legacy,
		trustPolicies:    trustPolicies,
		namespace:        namespace,
	}, nil
}

// Name returns the name of the cosign verifier
func (v *cosignVerifier) Name() string {
	return v.name
}

// Type returns 'cosign' as the type of the verifier
func (v *cosignVerifier) Type() string {
	return verifierType
}

// CanVerify returns true if the referenceDescriptor's artifact type is in the list of artifact types supported by the verifier
func (v *cosignVerifier) CanVerify(_ context.Context, referenceDescriptor ocispecs.ReferenceDescriptor) bool {
	for _, at := range v.artifactTypes {
		if at == "*" || at == referenceDescriptor.ArtifactType {
			return true
		}
	}
	return false
}

func (v *cosignVerifier) Verify(ctx context.Context, subjectReference common.Reference, referenceDescriptor ocispecs.ReferenceDescriptor, referrerStore referrerstore.ReferrerStore) (verifier.VerifierResult, error) {
	if v.isLegacy {
		return v.verifyLegacy(ctx, subjectReference, referenceDescriptor, referrerStore)
	}
	return v.verifyInternal(ctx, subjectReference, referenceDescriptor, referrerStore)
}

func (v *cosignVerifier) verifyInternal(ctx context.Context, subjectReference common.Reference, referenceDescriptor ocispecs.ReferenceDescriptor, referrerStore referrerstore.ReferrerStore) (verifier.VerifierResult, error) {
	// get the trust policy for the reference
	trustPolicy, err := v.trustPolicies.GetScopedPolicy(subjectReference.Original)
	if err != nil {
		return errorToVerifyResult(v.name, v.verifierType, err), nil
	}
	logger.GetLogger(ctx, logOpt).Debugf("selected trust policy %s for reference %s", trustPolicy.GetName(), subjectReference.Original)

	// get the map of keys and relevant cosign options for that reference
	keysMap, cosignOpts, err := getKeyMapOpts(ctx, trustPolicy, v.namespace)
	if err != nil {
		return errorToVerifyResult(v.name, v.verifierType, err), nil
	}

	// get the reference manifest (cosign oci image)
	referenceManifest, err := referrerStore.GetReferenceManifest(ctx, subjectReference, referenceDescriptor)
	if err != nil {
		return errorToVerifyResult(v.name, v.verifierType, re.ErrorCodeVerifyPluginFailure.WithDetail(fmt.Sprintf("Failed to get Cosign signature metadata for %s", referenceDescriptor.Digest)).WithError(err)), nil
	}

	// manifest must be an OCI Image
	if referenceManifest.MediaType != imgspec.MediaTypeImageManifest {
		return errorToVerifyResult(v.name, v.verifierType, re.ErrorCodeVerifyPluginFailure.WithDetail("The artifact metadata is not an OCI image")), nil
	}

	// get the subject image descriptor
	subjectDesc, err := referrerStore.GetSubjectDescriptor(ctx, subjectReference)
	if err != nil {
		return errorToVerifyResult(v.name, v.verifierType, re.ErrorCodeVerifyReferenceFailure.WithDetail(fmt.Sprintf("Failed to validate the Cosign signature of the artifact: %+v", subjectReference)).WithError(err)), nil
	}

	// create the hash of the subject image descriptor (used as the hashed payload)
	subjectDescHash := v1.Hash{
		Algorithm: subjectDesc.Digest.Algorithm().String(),
		Hex:       subjectDesc.Digest.Hex(),
	}

	sigExtensions := make([]cosignExtensionList, 0)
	hasValidSignature := false
	// check each signature found
	for _, blob := range referenceManifest.Blobs {
		extensionListEntry := cosignExtensionList{
			Signature:     blob.Annotations[static.SignatureAnnotationKey],
			Verifications: make([]cosignExtension, 0),
		}
		// fetch the blob content of the signature from the referrer store
		blobBytes, err := referrerStore.GetBlobContent(ctx, subjectReference, blob.Digest)
		if err != nil {
			return errorToVerifyResult(v.name, v.verifierType, re.ErrorCodeGetBlobContentFailure.WithDetail(fmt.Sprintf("Failed to get Cosign signature with digest %s", blob.Digest)).WithError(err)), nil
		}
		// convert the blob to a static signature
		staticOpts, err := staticLayerOpts(blob)
		if err != nil {
			return errorToVerifyResult(v.name, v.verifierType, re.ErrorCodeVerifyPluginFailure.WithDetail(fmt.Sprintf("Failed to parse Cosign signature with digest %s", blob.Digest)).WithError(err)), nil
		}
		sig, err := static.NewSignature(blobBytes, blob.Annotations[static.SignatureAnnotationKey], staticOpts...)
		if err != nil {
			return errorToVerifyResult(v.name, v.verifierType, re.ErrorCodeVerifyPluginFailure.WithDetail("Failed to validate the Cosign signature").WithError(err)), nil
		}
		if len(keysMap) > 0 {
			// if keys are found, perform verification with keys
			var verifications []cosignExtension
			verifications, hasValidSignature, err = verifyWithKeys(ctx, keysMap, sig, blob.Annotations[static.SignatureAnnotationKey], blobBytes, staticOpts, &cosignOpts, subjectDescHash)
			if err != nil {
				return errorToVerifyResult(v.name, v.verifierType, re.ErrorCodeVerifyPluginFailure.WithDetail("Failed to validate the Cosign signature with keys").WithError(err)), nil
			}
			extensionListEntry.Verifications = append(extensionListEntry.Verifications, verifications...)
		} else {
			// if no keys are found, perform keyless verification
			var extension cosignExtension
			extension, hasValidSignature = verifyKeyless(ctx, sig, &cosignOpts, subjectDescHash)
			extensionListEntry.Verifications = append(extensionListEntry.Verifications, extension)
		}
		sigExtensions = append(sigExtensions, extensionListEntry)
	}

	if hasValidSignature {
		return verifier.NewVerifierResult(
			"",
			v.name,
			v.verifierType,
			"Verification success. Valid signatures found. Please refer to extensions field for verifications performed.",
			true,
			nil,
			Extension{SignatureExtension: sigExtensions, TrustPolicy: trustPolicy.GetName()},
		), nil
	}

	errorResult := errorToVerifyResult(v.name, v.verifierType, fmt.Errorf("no valid Cosign signatures found"))
	errorResult.Extensions = Extension{SignatureExtension: sigExtensions, TrustPolicy: trustPolicy.GetName()}
	return errorResult, nil
}

// **LEGACY** This implementation will be removed in Ratify v2.0.0. Verify verifies the subject reference using the cosign verifier.
func (v *cosignVerifier) verifyLegacy(ctx context.Context, subjectReference common.Reference, referenceDescriptor ocispecs.ReferenceDescriptor, referrerStore referrerstore.ReferrerStore) (verifier.VerifierResult, error) {
	cosignOpts := &cosign.CheckOpts{
		ClaimVerifier: cosign.SimpleClaimVerifier,
	}

	var ecdsaVerifier signature.Verifier
	var roots *x509.CertPool
	var err error
	if v.config.KeyRef != "" {
		ecdsaVerifier, err = loadPublicKey(v.config.KeyRef)
		if err != nil {
			return errorToVerifyResult(v.name, v.verifierType, fmt.Errorf("failed to load public key: %w", err)), nil
		}
		cosignOpts.SigVerifier = ecdsaVerifier
	} else {
		roots, err = fulcio.GetRoots()
		if err != nil {
			return errorToVerifyResult(v.name, v.verifierType, fmt.Errorf("failed to get fulcio roots: %w", err)), nil
		}
		cosignOpts.RootCerts = roots
		if cosignOpts.RootCerts == nil {
			return errorToVerifyResult(v.name, v.verifierType, fmt.Errorf("failed to initialize root certificates")), nil
		}
	}

	if v.config.RekorURL != "" {
		cosignOpts.RekorClient, err = rekor.NewClient(v.config.RekorURL)
		if err != nil {
			return errorToVerifyResult(v.name, v.verifierType, fmt.Errorf("failed to create Rekor client from URL %s: %w", v.config.RekorURL, err)), nil
		}
		cosignOpts.CTLogPubKeys, err = cosign.GetCTLogPubs(ctx)
		if err != nil {
			return errorToVerifyResult(v.name, v.verifierType, fmt.Errorf("failed to set Certificate Transparency Log public keys: %w", err)), nil
		}
		// Fetches the Rekor public keys from the Rekor server
		cosignOpts.RekorPubKeys, err = cosign.GetRekorPubs(ctx)
		if err != nil {
			return errorToVerifyResult(v.name, v.verifierType, fmt.Errorf("failed to set Rekor public keys: %w", err)), nil
		}
	} else {
		// if no rekor url is provided, turn off transparency log verification and ignore SCTs
		cosignOpts.IgnoreTlog = true
		cosignOpts.IgnoreSCT = true
	}

	referenceManifest, err := referrerStore.GetReferenceManifest(ctx, subjectReference, referenceDescriptor)
	if err != nil {
		return errorToVerifyResult(v.name, v.verifierType, fmt.Errorf("failed to get reference manifest: %w", err)), nil
	}

	// manifest must be an OCI Image
	if referenceManifest.MediaType != imgspec.MediaTypeImageManifest {
		return errorToVerifyResult(v.name, v.verifierType, fmt.Errorf("reference manifest is not an image")), nil
	}

	subjectDesc, err := referrerStore.GetSubjectDescriptor(ctx, subjectReference)
	if err != nil {
		return errorToVerifyResult(v.name, v.verifierType, fmt.Errorf("failed to create subject hash: %w", err)), nil
	}
	subjectDescHash := v1.Hash{
		Algorithm: subjectDesc.Digest.Algorithm().String(),
		Hex:       subjectDesc.Digest.Hex(),
	}

	sigExtensions := make([]cosignExtension, 0)
	signatures := []oci.Signature{}
	for _, blob := range referenceManifest.Blobs {
		blobBytes, err := referrerStore.GetBlobContent(ctx, subjectReference, blob.Digest)
		if err != nil {
			return errorToVerifyResult(v.name, v.verifierType, fmt.Errorf("failed to get blob content: %w", err)), nil
		}
		staticOpts, err := staticLayerOpts(blob)
		if err != nil {
			return errorToVerifyResult(v.name, v.verifierType, fmt.Errorf("failed to parse static signature opts: %w", err)), nil
		}
		sig, err := static.NewSignature(blobBytes, blob.Annotations[static.SignatureAnnotationKey], staticOpts...)
		if err != nil {
			return errorToVerifyResult(v.name, v.verifierType, fmt.Errorf("failed to generate static signature: %w", err)), nil
		}
		// The verification will return an error if the signature is not valid.
		bundleVerified, err := cosign.VerifyImageSignature(ctx, sig, subjectDescHash, cosignOpts)
		extension := cosignExtension{
			SignatureDigest: blob.Digest,
			IsSuccess:       true,
			BundleVerified:  bundleVerified,
		}
		if err != nil {
			extension.IsSuccess = false
			extension.Err = err.Error()
		} else {
			signatures = append(signatures, sig)
		}
		sigExtensions = append(sigExtensions, extension)
	}

	if len(signatures) > 0 {
		return verifier.NewVerifierResult(
			"",
			v.name,
			v.verifierType,
			"Verification success. Valid signatures found",
			true,
			nil,
			LegacyExtension{SignatureExtension: sigExtensions},
		), nil
	}

	errorResult := errorToVerifyResult(v.name, v.verifierType, fmt.Errorf("no valid signatures found"))
	errorResult.Extensions = LegacyExtension{SignatureExtension: sigExtensions}
	return errorResult, nil
}

// GetNestedReferences returns the nested reference artifact types configured
func (v *cosignVerifier) GetNestedReferences() []string {
	return v.nestedReferences
}

// ParseVerifierConfig parses the verifier config and returns a PluginConfig
func parseVerifierConfig(verifierConfig config.VerifierConfig) (*PluginConfig, error) {
	verifierName, hasName := verifierConfig[types.Name].(string)
	if !hasName {
		return nil, re.ErrorCodeConfigInvalid.NewError(re.Verifier, "", re.EmptyLink, nil, "missing name in verifier config", re.HideStackTrace)
	}
	conf := PluginConfig{}

	verifierConfigBytes, err := json.Marshal(verifierConfig)
	if err != nil {
		return nil, re.ErrorCodeConfigInvalid.NewError(re.Verifier, verifierName, re.EmptyLink, err, nil, re.HideStackTrace)
	}

	if err := json.Unmarshal(verifierConfigBytes, &conf); err != nil {
		return nil, re.ErrorCodeConfigInvalid.NewError(re.Verifier, verifierName, re.EmptyLink, err, fmt.Sprintf("failed to unmarshal to cosign verifier config from: %+v.", verifierConfig), re.HideStackTrace)
	}

	// if Type is not provided, use the Name as the Type (backwards compatibility)
	if conf.Type == "" {
		conf.Type = conf.Name
	}

	if conf.ArtifactTypes == "" {
		return nil, re.ErrorCodeConfigInvalid.NewError(re.Verifier, verifierName, re.EmptyLink, nil, "missing artifactTypes in verifier config", re.HideStackTrace)
	}

	return &conf, nil
}

// LoadPublicKey loads the public key from the keyRef
func loadPublicKey(keyRef string) (verifier signature.Verifier, err error) {
	keyPath := filepath.Clean(utils.ReplaceHomeShortcut(keyRef))
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	// PEM encoded file.
	ed, err := cosign.PemToECDSAKey(raw)
	if err != nil {
		return nil, errors.Wrap(err, "pem to ecdsa")
	}
	return signature.LoadECDSAVerifier(ed, crypto.SHA256)
}

// StaticLayerOpts builds the cosign options for static layer signatures
func staticLayerOpts(desc imgspec.Descriptor) ([]static.Option, error) {
	options := []static.Option{}
	options = append(options, static.WithAnnotations(desc.Annotations))
	cert := desc.Annotations[static.CertificateAnnotationKey]
	chain := desc.Annotations[static.ChainAnnotationKey]
	if cert != "" && chain != "" {
		options = append(options, static.WithCertChain([]byte(cert), []byte(chain)))
	}
	var rekorBundle bundle.RekorBundle
	if val, ok := desc.Annotations[static.BundleAnnotationKey]; ok {
		if err := json.Unmarshal([]byte(val), &rekorBundle); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal bundle from blob payload")
		}
		options = append(options, static.WithBundle(&rekorBundle))
	}

	return options, nil
}

// ErrorToVerifyResult returns a verifier result with the error message and isSuccess set to false
func errorToVerifyResult(name string, verifierType string, err error) verifier.VerifierResult {
	verifierErr := re.ErrorCodeVerifyReferenceFailure.WithDetail("Failed to validate the Cosign signature").WithError(err)
	return verifier.NewVerifierResult(
		"",
		name,
		verifierType,
		"",
		false,
		&verifierErr,
		nil,
	)
}

// decodeASN1Signature decodes the ASN.1 signature to raw signature bytes
func decodeASN1Signature(sig []byte) ([]byte, error) {
	// Convert the ASN.1 Sequence to a concatenated r||s byte string
	// This logic is based from https://cs.opensource.google/go/go/+/refs/tags/go1.17.3:src/crypto/ecdsa/ecdsa.go;l=339
	var (
		r, s  = &big.Int{}, &big.Int{}
		inner cryptobyte.String
	)

	rawSigBytes := sig
	input := cryptobyte.String(sig)
	if input.ReadASN1(&inner, asn1.SEQUENCE) {
		// if ASN.1 sequence is found, parse r and s
		if !inner.ReadASN1Integer(r) {
			return nil, fmt.Errorf("failed parsing r")
		}
		if !inner.ReadASN1Integer(s) {
			return nil, fmt.Errorf("failed parsing s")
		}
		if !inner.Empty() {
			return nil, fmt.Errorf("failed parsing signature")
		}
		rawSigBytes = []byte{}
		rawSigBytes = append(rawSigBytes, r.Bytes()...)
		rawSigBytes = append(rawSigBytes, s.Bytes()...)
	}

	return rawSigBytes, nil
}

// verifyWithKeys verifies the signature with the keys map and returns the verification results
func verifyWithKeys(ctx context.Context, keysMap map[PKKey]keymanagementprovider.PublicKey, sig oci.Signature, sigEncoded string, payload []byte, staticOpts []static.Option, cosignOpts *cosign.CheckOpts, subjectDescHash v1.Hash) ([]cosignExtension, bool, error) {
	// check each key in the map of keys returned by the trust policy
	var err error
	verifications := make([]cosignExtension, 0)
	hasValidSignature := false
	for mapKey, pubKey := range keysMap {
		hashType := crypto.SHA256
		// default hash type is SHA256 but for AKV scenarios, the hash type is determined by the key size
		// TODO: investigate if it's possible to extract hash type from sig directly. This is a workaround for now
		if pubKey.ProviderType == azurekeyvault.ProviderName {
			hashType, sig, err = processAKVSignature(sigEncoded, sig, pubKey.Key, payload, staticOpts)
			if err != nil {
				return verifications, false, re.ErrorCodeVerifyPluginFailure.WithDetail("Failed to validate the Cosign signature generated by Azure Key Vault").WithError(err)
			}
		}

		// return the correct verifier based on public key type and bytes
		verifier, err := signature.LoadVerifier(pubKey.Key, hashType)
		if err != nil {
			return verifications, false, re.ErrorCodeVerifyPluginFailure.WithDetail(fmt.Sprintf("Failed to load public key from provider [%s] name [%s] version [%s]", mapKey.Provider, mapKey.Name, mapKey.Version)).WithError(err)
		}
		cosignOpts.SigVerifier = verifier
		// verify signature with cosign options + perform bundle verification
		bundleVerified, err := cosign.VerifyImageSignature(ctx, sig, subjectDescHash, cosignOpts)
		extension := cosignExtension{
			IsSuccess:      true,
			BundleVerified: bundleVerified,
			KeyInformation: mapKey,
		}
		if err != nil {
			extension.IsSuccess = false
			extension.Err = err.Error()
		} else {
			extension.Summary = verificationPerformedMessage(bundleVerified, cosignOpts)
			hasValidSignature = true
		}
		verifications = append(verifications, extension)
	}
	return verifications, hasValidSignature, nil
}

// verifyKeyless performs keyless verification and returns the verification results
func verifyKeyless(ctx context.Context, sig oci.Signature, cosignOpts *cosign.CheckOpts, subjectDescHash v1.Hash) (cosignExtension, bool) {
	// verify signature with cosign options + perform bundle verification
	hasValidSignature := false
	bundleVerified, err := cosign.VerifyImageSignature(ctx, sig, subjectDescHash, cosignOpts)
	extension := cosignExtension{
		IsSuccess:      true,
		BundleVerified: bundleVerified,
	}
	if err != nil {
		extension.IsSuccess = false
		extension.Err = err.Error()
	} else {
		extension.Summary = verificationPerformedMessage(bundleVerified, cosignOpts)
		hasValidSignature = true
	}
	return extension, hasValidSignature
}

// getKeyMapOptsDefault returns the map of keys and cosign options for the reference
func getKeyMapOptsDefault(ctx context.Context, trustPolicy TrustPolicy, namespace string) (map[PKKey]keymanagementprovider.PublicKey, cosign.CheckOpts, error) {
	// get the map of keys for that reference
	keysMap, err := trustPolicy.GetKeys(ctx, namespace)
	if err != nil {
		return nil, cosign.CheckOpts{}, err
	}

	// get the cosign options for that trust policy
	cosignOpts, err := trustPolicy.GetCosignOpts(ctx)
	if err != nil {
		return nil, cosign.CheckOpts{}, err
	}

	return keysMap, cosignOpts, nil
}

// processAKVSignature processes the AKV signature and returns the hash type, signature and error
func processAKVSignature(sigEncoded string, staticSig oci.Signature, publicKey crypto.PublicKey, payloadBytes []byte, staticOpts []static.Option) (crypto.Hash, oci.Signature, error) {
	var hashType crypto.Hash
	switch keyType := publicKey.(type) {
	case *rsa.PublicKey:
		switch keyType.Size() {
		case 256:
			hashType = crypto.SHA256
		case 384:
			hashType = crypto.SHA384
		case 512:
			hashType = crypto.SHA512
		default:
			return crypto.SHA256, nil, fmt.Errorf("RSA key check: unsupported key size: %d", keyType.Size())
		}

		// TODO: remove section after fix for bug in cosign azure key vault implementation
		// tracking issue: https://github.com/sigstore/sigstore/issues/1384
		// summary: azure keyvault implementation ASN.1 encodes sig after online signing with keyvault
		// EC verifiers in cosign have built in ASN.1 decoding, but RSA verifiers do not
		base64DecodedBytes, err := base64.StdEncoding.DecodeString(sigEncoded)
		if err != nil {
			return crypto.SHA256, nil, re.ErrorCodeVerifyPluginFailure.WithDetail("RSA key check: failed to decode base64 signature").WithError(err)
		}
		// decode ASN.1 signature to raw signature if it is ASN.1 encoded
		decodedSigBytes, err := decodeASN1Signature(base64DecodedBytes)
		if err != nil {
			return crypto.SHA256, nil, re.ErrorCodeVerifyPluginFailure.WithDetail("RSA key check: failed to decode ASN.1 signature").WithError(err)
		}
		encodedBase64SigBytes := base64.StdEncoding.EncodeToString(decodedSigBytes)
		staticSig, err = static.NewSignature(payloadBytes, encodedBase64SigBytes, staticOpts...)
		if err != nil {
			return crypto.SHA256, nil, re.ErrorCodeVerifyPluginFailure.WithDetail("RSA key check: failed to generate static signature").WithError(err)
		}
	case *ecdsa.PublicKey:
		switch keyType.Curve {
		case elliptic.P256():
			hashType = crypto.SHA256
		case elliptic.P384():
			hashType = crypto.SHA384
		case elliptic.P521():
			hashType = crypto.SHA512
		default:
			return crypto.SHA256, nil, fmt.Errorf("ECDSA key check: unsupported key curve [%s]", keyType.Params().Name)
		}
	default:
		return crypto.SHA256, nil, fmt.Errorf("unsupported public key type [%T]", publicKey)
	}
	return hashType, staticSig, nil
}

// verificationPerformedMessage returns a string list of all verifications performed
// based on https://github.com/sigstore/cosign/blob/5ae2e31c30ee87e035cc57ebbbe2ecf3b6549ff5/cmd/cosign/cli/verify/verify.go#L318
func verificationPerformedMessage(bundleVerified bool, co *cosign.CheckOpts) []string {
	var messages []string
	if co.ClaimVerifier != nil {
		if co.Annotations != nil {
			messages = append(messages, annotationMessage)
		}
		messages = append(messages, claimsMessage)
	}
	if bundleVerified {
		messages = append(messages, offlineBundleMessage)
	} else if co.RekorClient != nil {
		messages = append(messages, rekorClaimsMessage)
		messages = append(messages, rekorSigMessage)
	}
	// if no SigVerifier is provided, fulcio root certs are assumed to be used (keyless)
	if co.SigVerifier != nil {
		messages = append(messages, sigVerifierMessage)
	} else {
		messages = append(messages, certVerifierMessage)
	}
	return messages
}
