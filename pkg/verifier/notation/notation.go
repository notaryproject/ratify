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
	paths "path/filepath"
	"strings"

	ratifyconfig "github.com/ratify-project/ratify/config"
	re "github.com/ratify-project/ratify/errors"
	"github.com/ratify-project/ratify/internal/logger"
	"github.com/ratify-project/ratify/pkg/common"
	"github.com/ratify-project/ratify/pkg/homedir"

	"github.com/notaryproject/notation-go/log"
	"github.com/ratify-project/ratify/pkg/ocispecs"
	"github.com/ratify-project/ratify/pkg/referrerstore"
	"github.com/ratify-project/ratify/pkg/verifier"
	"github.com/ratify-project/ratify/pkg/verifier/config"
	"github.com/ratify-project/ratify/pkg/verifier/factory"
	"github.com/ratify-project/ratify/pkg/verifier/types"

	"github.com/notaryproject/notation-core-go/revocation"
	"github.com/notaryproject/notation-core-go/revocation/purpose"
	_ "github.com/notaryproject/notation-core-go/signature/cose" // register COSE signature
	_ "github.com/notaryproject/notation-core-go/signature/jws"  // register JWS signature
	"github.com/notaryproject/notation-go"
	notationVerifier "github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	verifierType                   = "notation"
	defaultCertPath                = "ratify-certs/notation/truststore"
	trustStoreTypeCA               = string(truststore.TypeCA)
	trustStoreTypeSigningAuthority = string(truststore.TypeSigningAuthority)
	trustStoreTypeTSA              = string(truststore.TypeTSA)
)

// NotationPluginVerifierConfig describes the configuration of notation verifier
type NotationPluginVerifierConfig struct { //nolint:revive // ignore linter to have unique type name
	Name          string `json:"name"`
	ArtifactTypes string `json:"artifactTypes"`

	// VerificationCerts is array of directories containing certificates.
	VerificationCerts []string `json:"verificationCerts"`
	// VerificationCertStores defines a collection of Notary Project Trust Stores.
	// VerificationCertStores accepts new format map[string]map[string][]string
	// {
	//   "ca": {
	//     "certs": {"kv1", "kv2"},
	//   },
	//   "signingauthority": {
	//     "certs": {"kv3"}
	//   },
	// }
	// VerificationCertStores accepts legacy format map[string][]string as well.
	// {
	//   "certs": {"kv1", "kv2"},
	// },
	VerificationCertStores verificationCertStores `json:"verificationCertStores"`
	// TrustPolicyDoc represents a trustpolicy.json document. Reference: https://pkg.go.dev/github.com/notaryproject/notation-go@v0.12.0-beta.1.0.20221125022016-ab113ebd2a6c/verifier/trustpolicy#Document
	TrustPolicyDoc trustpolicy.Document `json:"trustPolicyDoc"`
}

type notationPluginVerifier struct {
	name             string
	verifierType     string
	artifactTypes    []string
	notationVerifier *notation.Verifier
}

type notationPluginVerifierFactory struct{}

func init() {
	factory.Register(verifierType, &notationPluginVerifierFactory{})
}

func (f *notationPluginVerifierFactory) Create(_ string, verifierConfig config.VerifierConfig, pluginDirectory string, namespace string) (verifier.ReferenceVerifier, error) {
	ctx := context.Background()
	logger.GetLogger(ctx, logOpt).Debugf("creating Notation verifier with config %v, namespace '%v'", verifierConfig, namespace)
	verifierName := fmt.Sprintf("%s", verifierConfig[types.Name])
	verifierTypeStr := ""
	if _, ok := verifierConfig[types.Type]; ok {
		verifierTypeStr = fmt.Sprintf("%s", verifierConfig[types.Type])
	}
	conf, err := parseVerifierConfig(verifierConfig, namespace)
	if err != nil {
		return nil, re.ErrorCodePluginInitFailure.WithDetail("Failed to create the Notation Verifier").WithError(err)
	}
	verifyService, err := getVerifierService(ctx, conf, pluginDirectory, CreateCRLHandlerFromConfig())
	if err != nil {
		return nil, re.ErrorCodePluginInitFailure.WithDetail("Failed to create the Notation Verifier").WithError(err)
	}

	artifactTypes := strings.Split(conf.ArtifactTypes, ",")
	return &notationPluginVerifier{
		name:             verifierName,
		verifierType:     verifierTypeStr,
		artifactTypes:    artifactTypes,
		notationVerifier: &verifyService,
	}, nil
}

func (v *notationPluginVerifier) Name() string {
	return v.name
}

func (v *notationPluginVerifier) Type() string {
	return v.verifierType
}

func (v *notationPluginVerifier) CanVerify(_ context.Context, referenceDescriptor ocispecs.ReferenceDescriptor) bool {
	for _, at := range v.artifactTypes {
		if at == "*" || at == referenceDescriptor.ArtifactType {
			return true
		}
	}
	return false
}

func (v *notationPluginVerifier) Verify(ctx context.Context,
	subjectReference common.Reference,
	referenceDescriptor ocispecs.ReferenceDescriptor,
	store referrerstore.ReferrerStore) (verifier.VerifierResult, error) {
	extensions := make(map[string]string)

	subjectDesc, err := store.GetSubjectDescriptor(ctx, subjectReference)
	if err != nil {
		return verifier.VerifierResult{IsSuccess: false}, re.ErrorCodeVerifyReferenceFailure.WithDetail(fmt.Sprintf("Failed to validate the Notation signature of the artifact: %+v", subjectReference)).WithError(err)
	}

	referenceManifest, err := store.GetReferenceManifest(ctx, subjectReference, referenceDescriptor)
	if err != nil {
		return verifier.VerifierResult{IsSuccess: false}, re.ErrorCodeVerifyReferenceFailure.WithDetail(fmt.Sprintf("Failed to validate the Notation signature: %+v", referenceDescriptor)).WithError(err)
	}

	if len(referenceManifest.Blobs) != 1 {
		return verifier.VerifierResult{IsSuccess: false}, re.ErrorCodeVerifyReferenceFailure.WithDetail(fmt.Sprintf("Notation signature manifest requires exactly one signature envelope blob, got %d", len(referenceManifest.Blobs))).WithRemediation(fmt.Sprintf("Please inspect the artifact [%s@%s] is correctly signed by Notation signer", subjectReference.Path, referenceDescriptor.Digest.String()))
	}
	blobDesc := referenceManifest.Blobs[0]
	refBlob, err := store.GetBlobContent(ctx, subjectReference, blobDesc.Digest)
	if err != nil {
		return verifier.VerifierResult{IsSuccess: false}, re.ErrorCodeVerifyReferenceFailure.WithDetail(fmt.Sprintf("Failed to validate the Notation signature of the artifact: %+v", subjectReference)).WithError(err)
	}

	// TODO: notation verify API only accepts digested reference now.
	// Pass in tagged reference instead once notation-go supports it.
	subjectRef := fmt.Sprintf("%s@%s", subjectReference.Path, subjectReference.Digest.String())
	outcome, err := v.verifySignature(ctx, subjectRef, blobDesc.MediaType, subjectDesc.Descriptor, refBlob)
	if err != nil {
		return verifier.VerifierResult{IsSuccess: false, Extensions: extensions}, re.ErrorCodeVerifyReferenceFailure.WithDetail(fmt.Sprintf("Failed to validate the Notation signature: %+v", referenceDescriptor)).WithError(err)
	}

	// Note: notation verifier already validates certificate chain is not empty.
	cert := outcome.EnvelopeContent.SignerInfo.CertificateChain[0]
	extensions["Issuer"] = cert.Issuer.String()
	extensions["SN"] = cert.Subject.String()

	return verifier.NewVerifierResult("", v.name, v.verifierType, "Notation signature verification success", true, nil, extensions), nil
}

func getVerifierService(ctx context.Context, conf *NotationPluginVerifierConfig, pluginDirectory string, revocationFactory RevocationFactory) (notation.Verifier, error) {
	store, err := newTrustStore(conf.VerificationCerts, conf.VerificationCertStores)
	if err != nil {
		return nil, err
	}

	// revocation check using corecrl from notation-core-go and crl from notation-go
	// This is the implementation for revocation check from notation cli to support crl and cache configurations
	// removed timeout
	// Related PR: notaryproject/notation#1043
	// Related File: https://github.com/notaryproject/notation/commits/main/cmd/notation/verify.go5
	crlFetcher, err := revocationFactory.NewFetcher()
	if err != nil {
		logger.GetLogger(ctx, logOpt).Warnf("Unable to create CRL fetcher for notation verifier %s with error: %s", conf.Name, err)
	}
	revocationCodeSigningValidator, err := revocationFactory.NewValidator(revocation.Options{
		CRLFetcher:       crlFetcher,
		CertChainPurpose: purpose.CodeSigning,
	})
	if err != nil {
		return nil, err
	}
	revocationTimestampingValidator, err := revocationFactory.NewValidator(revocation.Options{
		CRLFetcher:       crlFetcher,
		CertChainPurpose: purpose.Timestamping,
	})
	if err != nil {
		return nil, err
	}

	verifier, err := notationVerifier.NewWithOptions(&conf.TrustPolicyDoc, store, NewRatifyPluginManager(pluginDirectory), notationVerifier.VerifierOptions{
		RevocationCodeSigningValidator:  revocationCodeSigningValidator,
		RevocationTimestampingValidator: revocationTimestampingValidator,
	})
	if err != nil {
		return nil, re.ErrorCodePluginInitFailure.WithDetail("Failed to create the Notation Verifier").WithError(err)
	}
	return verifier, nil
}

func (v *notationPluginVerifier) verifySignature(ctx context.Context, subjectRef, mediaType string, subjectDesc oci.Descriptor, refBlob []byte) (*notation.VerificationOutcome, error) {
	opts := notation.VerifierVerifyOptions{
		SignatureMediaType: mediaType,
		ArtifactReference:  subjectRef,
	}
	ctx = log.WithLogger(ctx, logger.GetLogger(ctx, logOpt))

	return (*v.notationVerifier).Verify(ctx, subjectDesc, refBlob, opts)
}

func parseVerifierConfig(verifierConfig config.VerifierConfig, _ string) (*NotationPluginVerifierConfig, error) {
	conf := &NotationPluginVerifierConfig{}

	verifierConfigBytes, err := json.Marshal(verifierConfig)
	if err != nil {
		return nil, re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Failed to parse the Notation Verifier configuration: %+v", verifierConfig)).WithError(err)
	}

	if err := json.Unmarshal(verifierConfigBytes, &conf); err != nil {
		return nil, re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Failed to parse the Notation Verifier configuration: %+v", verifierConfig)).WithError(err)
	}

	defaultCertsDir := paths.Join(homedir.Get(), ratifyconfig.ConfigFileDir, defaultCertPath)
	conf.VerificationCerts = append(conf.VerificationCerts, defaultCertsDir)
	if len(conf.VerificationCertStores) > 0 {
		if err := normalizeVerificationCertsStores(conf); err != nil {
			return nil, err
		}
	}
	return conf, nil
}

// signatures should not have nested references
func (v *notationPluginVerifier) GetNestedReferences() []string {
	return []string{}
}

// normalizeVerificationCertsStores normalize the structure does not match the latest spec
func normalizeVerificationCertsStores(conf *NotationPluginVerifierConfig) error {
	isCertStoresByType, isLegacyCertStore := false, false
	for key := range conf.VerificationCertStores {
		if key != trustStoreTypeCA && key != trustStoreTypeSigningAuthority && key != trustStoreTypeTSA {
			isLegacyCertStore = true
			logger.GetLogger(context.Background(), logOpt).Debugf("Get VerificationCertStores in legacy format")
		} else {
			isCertStoresByType = true
		}
	}
	if isCertStoresByType && isLegacyCertStore {
		// showing configuration content in the log with error details for better user experience
		err := re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("The verificationCertStores is misconfigured with both legacy and new formats: %+v", conf)).WithRemediation("Please provide only one format for the VerificationCertStores. Refer to the Notation Verifier configuration guide: https://ratify.dev/docs/plugins/verifier/notation#configuration")
		logger.GetLogger(context.Background(), logOpt).Error(err)
		return err
	} else if !isCertStoresByType && isLegacyCertStore {
		legacyCertStore, err := normalizeLegacyCertStore(conf)
		if err != nil {
			return err
		}
		// support legacy verifier config format for backward compatibility
		// normalize <store>:<certs> to ca:<store><certs> if no store type is provided
		conf.VerificationCertStores = verificationCertStores{
			trustStoreTypeCA: legacyCertStore,
		}
	}
	return nil
}

// TODO: remove this function once the refactor is done [refactore tracking issue](https://github.com/ratify-project/ratify/issues/1752)
func normalizeLegacyCertStore(conf *NotationPluginVerifierConfig) (map[string]interface{}, error) {
	legacyCertStoreBytes, err := json.Marshal(conf.VerificationCertStores)
	if err != nil {
		return nil, re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Failed to recognize `verificationCertStores` value of Notation Verifier configuration: %+v", conf.VerificationCertStores)).WithError(err)
	}
	var legacyCertStore map[string]interface{}
	if err := json.Unmarshal(legacyCertStoreBytes, &legacyCertStore); err != nil {
		return nil, re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("Failed to recognize `verificationCertStores` value of Notation Verifier configuration: %+v", conf.VerificationCertStores)).WithError(err)
	}
	return legacyCertStore, nil
}
