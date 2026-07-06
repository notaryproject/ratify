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
	"encoding/json"
	"fmt"

	"github.com/notaryproject/notation-core-go/revocation"
	"github.com/notaryproject/notation-core-go/revocation/purpose"
	notationgo "github.com/notaryproject/notation-go"
	notationregistry "github.com/notaryproject/notation-go/registry"
	notationverifier "github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	"github.com/notaryproject/ratify-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
)

type notationVerifierOptions struct {
	Name           string
	TrustPolicyDoc *trustpolicy.Document
	TrustStore     truststore.X509TrustStore
	CRL            crlOptions
}

type notationVerifier struct {
	name     string
	verifier notationgo.Verifier
}

func newNotationVerifier(opts *notationVerifierOptions) (*notationVerifier, error) {
	crlFetcher, err := createCRLFetcher(opts.CRL.Cache.Enabled)
	if err != nil {
		logrus.Warnf("failed to create CRL fetcher for notation verifier %s: %v", opts.Name, err)
	}

	codeSigningValidator, err := revocation.NewWithOptions(revocation.Options{
		CRLFetcher:       crlFetcher,
		CertChainPurpose: purpose.CodeSigning,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create code signing revocation validator: %w", err)
	}
	timestampingValidator, err := revocation.NewWithOptions(revocation.Options{
		CRLFetcher:       crlFetcher,
		CertChainPurpose: purpose.Timestamping,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create timestamping revocation validator: %w", err)
	}

	v, err := notationverifier.NewWithOptions(
		opts.TrustPolicyDoc,
		opts.TrustStore,
		nil,
		notationverifier.VerifierOptions{
			RevocationCodeSigningValidator:  codeSigningValidator,
			RevocationTimestampingValidator: timestampingValidator,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create notation verifier: %w", err)
	}

	return &notationVerifier{
		name:     opts.Name,
		verifier: v,
	}, nil
}

func (v *notationVerifier) Name() string {
	return v.name
}

func (v *notationVerifier) Type() string {
	return verifierTypeNotation
}

func (v *notationVerifier) Verifiable(artifact ocispec.Descriptor) bool {
	return artifact.ArtifactType == notationregistry.ArtifactTypeNotation && artifact.MediaType == ocispec.MediaTypeImageManifest
}

func (v *notationVerifier) Verify(ctx context.Context, opts *ratify.VerifyOptions) (*ratify.VerificationResult, error) {
	signatureDesc, err := v.getSignatureBlobDesc(ctx, opts.Store, opts.Repository, opts.ArtifactDescriptor)
	if err != nil {
		return nil, fmt.Errorf("failed to get signature blob descriptor: %w", err)
	}

	signatureBlob, err := opts.Store.FetchBlob(ctx, opts.Repository, signatureDesc)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch signature blob: %w", err)
	}

	result := &ratify.VerificationResult{
		Verifier: v,
	}
	verifyOpts := notationgo.VerifierVerifyOptions{
		SignatureMediaType: signatureDesc.MediaType,
		ArtifactReference:  opts.Repository + "@" + opts.SubjectDescriptor.Digest.String(),
	}
	outcome, err := v.verifier.Verify(ctx, opts.SubjectDescriptor, signatureBlob, verifyOpts)
	if err != nil {
		result.Err = err
		return result, nil
	}

	cert := outcome.EnvelopeContent.SignerInfo.CertificateChain[0]
	result.Detail = map[string]string{
		"Issuer": cert.Issuer.String(),
		"SN":     cert.Subject.String(),
	}
	result.Description = "Notation signature verification succeeded"
	return result, nil
}

func (v *notationVerifier) getSignatureBlobDesc(ctx context.Context, store ratify.Store, repo string, artifactDesc ocispec.Descriptor) (ocispec.Descriptor, error) {
	manifestBytes, err := store.FetchManifest(ctx, repo, artifactDesc)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to fetch manifest for artifact: %w", err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	if len(manifest.Layers) != 1 {
		return ocispec.Descriptor{}, fmt.Errorf("notation signature manifest requires exactly one signature envelope blob, got %d", len(manifest.Layers))
	}

	return manifest.Layers[0], nil
}
