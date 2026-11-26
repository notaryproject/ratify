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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-core-go/testhelper"
	notationregistry "github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify/v2/internal/verifier"
	_ "github.com/notaryproject/ratify/v2/internal/verifier/keyprovider/inlineprovider" // Register the inline key provider
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	testPluginName = "ratify-test"
	// The test plugin accepts a signature only if the trust policy lists this
	// identity, the way the AWS Signer plugin matches a signing profile ARN.
	testPluginIdentity = "arn:aws:signer:us-east-1:123456789012:/signing-profiles/trusted"
	testOtherIdentity  = "arn:aws:signer:us-east-1:123456789012:/signing-profiles/other"
	// Stands for the attributes a signing service adds for its plugin, e.g.
	// com.amazonaws.signer.signingProfileVersion.
	testPluginAttribute = "test.ratify.signingProfile"
	testRepository      = "registry.example.test/app"
	testPluginRegion    = "us-east-1"
)

// testPluginScript is a Notation verification plugin. It follows
// https://github.com/notaryproject/specifications/blob/v1.0.0/specs/plugin-extensibility.md
// Success requires both a trusted identity and pluginConfig aws-region, the
// way the AWS Signer plugin needs the signing-profile region.
const testPluginScript = `#!/bin/sh
case "$1" in
get-plugin-metadata)
  echo '{"name":"` + testPluginName + `","description":"test plugin","version":"1.0.0","url":"https://example.test","supportedContractVersions":["1.0"],"capabilities":["SIGNATURE_VERIFIER.TRUSTED_IDENTITY"]}'
  ;;
verify-signature)
  req="$(cat)"
  success=false
  case "$req" in
  *'"trustedIdentities":["` + testPluginIdentity + `"]'*)
    case "$req" in
    *'"aws-region":"` + testPluginRegion + `"'*) success=true ;;
    esac
    ;;
  esac
  echo '{"verificationResults":{"SIGNATURE_VERIFIER.TRUSTED_IDENTITY":{"success":'"$success"',"reason":"decided by the test plugin"}},"processedAttributes":["` + testPluginAttribute + `"]}'
  ;;
*)
  exit 1
  ;;
esac
`

// memoryStore serves the manifest and the envelope of one signature.
type memoryStore struct {
	content map[digest.Digest][]byte
}

func (s *memoryStore) Resolve(context.Context, string) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{}, fmt.Errorf("not implemented")
}

func (s *memoryStore) ListReferrers(context.Context, string, []string, func([]ocispec.Descriptor) error) error {
	return fmt.Errorf("not implemented")
}

func (s *memoryStore) FetchBlob(_ context.Context, _ string, desc ocispec.Descriptor) ([]byte, error) {
	return s.fetch(desc)
}

func (s *memoryStore) FetchManifest(_ context.Context, _ string, desc ocispec.Descriptor) ([]byte, error) {
	return s.fetch(desc)
}

func (s *memoryStore) fetch(desc ocispec.Descriptor) ([]byte, error) {
	if data, ok := s.content[desc.Digest]; ok {
		return data, nil
	}
	return nil, fmt.Errorf("%s not found", desc.Digest)
}

// installTestPlugin installs the test plugin the way `notation plugin install`
// lays plugins out and returns the plugin directory.
func installTestPlugin(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the test plugin is a shell script")
	}
	directory := t.TempDir()
	pluginDirectory := filepath.Join(directory, testPluginName)
	if err := os.Mkdir(pluginDirectory, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDirectory, "notation-"+testPluginName), []byte(testPluginScript), 0o755); err != nil { //nolint:gosec // the plugin must be executable
		t.Fatal(err)
	}
	return directory
}

// signWithPluginAttributes signs an image the way a signing service with a
// verification plugin does: the signature names the plugin and carries a
// critical attribute that only the plugin understands.
func signWithPluginAttributes(t *testing.T, pluginName string) *ratify.VerifyOptions {
	t.Helper()
	image := []byte(`{"schemaVersion":2}`)
	subject := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.FromBytes(image),
		Size:      int64(len(image)),
	}
	payload, err := json.Marshal(map[string]any{"targetArtifact": subject})
	if err != nil {
		t.Fatal(err)
	}

	root, leaf := testhelper.GetRSARootCertificate(), testhelper.GetRSALeafCertificate()
	signer, err := signature.NewLocalSigner([]*x509.Certificate{leaf.Cert, root.Cert}, leaf.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signature.NewEnvelope(jws.MediaTypeEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := envelope.Sign(&signature.SignRequest{
		Payload: signature.Payload{
			ContentType: "application/vnd.cncf.notary.payload.v1+json",
			Content:     payload,
		},
		Signer:        signer,
		SigningTime:   time.Now(),
		SigningScheme: signature.SigningSchemeX509,
		SigningAgent:  "ratify-test",
		ExtendedSignedAttributes: []signature.Attribute{
			{Key: "io.cncf.notary.verificationPlugin", Critical: true, Value: pluginName},
			{Key: testPluginAttribute, Critical: true, Value: testPluginIdentity + "/version"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	layer := ocispec.Descriptor{
		MediaType: jws.MediaTypeEnvelope,
		Digest:    digest.FromBytes(signed),
		Size:      int64(len(signed)),
	}
	manifest, err := json.Marshal(ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: notationregistry.ArtifactTypeNotation,
		Layers:       []ocispec.Descriptor{layer},
		Subject:      &subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact := ocispec.Descriptor{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: notationregistry.ArtifactTypeNotation,
		Digest:       digest.FromBytes(manifest),
		Size:         int64(len(manifest)),
	}
	return &ratify.VerifyOptions{
		Store: &memoryStore{content: map[digest.Digest][]byte{
			layer.Digest:    signed,
			artifact.Digest: manifest,
		}},
		Repository:         testRepository,
		SubjectDescriptor:  subject,
		ArtifactDescriptor: artifact,
	}
}

// newTestVerifier creates the verifier through the registered factory, with
// the parameters in the form they have in the Executor configuration.
func newTestVerifier(pluginDirectory string, pluginConfig map[string]string, trustedIdentities ...string) (ratify.Verifier, error) {
	root := testhelper.GetRSARootCertificate().Cert
	parameters := map[string]any{
		"trustedIdentities": trustedIdentities,
		"certificates": []any{
			map[string]any{
				"type": "ca",
				"inline": map[string]any{
					"certs": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})),
				},
			},
		},
	}
	if pluginDirectory != "" {
		parameters["pluginDirectory"] = pluginDirectory
	}
	if pluginConfig != nil {
		parameters["pluginConfig"] = pluginConfig
	}
	return verifier.New(verifier.NewOptions{
		Name:       testName,
		Type:       verifierTypeNotation,
		Parameters: parameters,
	}, nil)
}

func testPluginConfig(region string) map[string]string {
	return map[string]string{"aws-region": region}
}

func TestVerifySignatureThatNeedsPlugin(t *testing.T) {
	withPlugin := installTestPlugin(t)
	withoutPlugin := t.TempDir()
	region := testPluginConfig(testPluginRegion)

	tests := []struct {
		name            string
		pluginDirectory string
		pluginConfig    map[string]string
		signedFor       string
		identity        string
		expectedErr     string // empty when the signature must verify
	}{
		{
			name:            "plugin installed, identity trusted, region set",
			pluginDirectory: withPlugin,
			pluginConfig:    region,
			signedFor:       testPluginName,
			identity:        testPluginIdentity,
		},
		{
			name:            "plugin installed and identity not trusted",
			pluginDirectory: withPlugin,
			pluginConfig:    region,
			signedFor:       testPluginName,
			identity:        testOtherIdentity,
			expectedErr:     "trusted identify verification by plugin",
		},
		{
			name:            "pluginConfig aws-region missing",
			pluginDirectory: withPlugin,
			signedFor:       testPluginName,
			identity:        testPluginIdentity,
			expectedErr:     "trusted identify verification by plugin",
		},
		{
			name:            "pluginConfig aws-region different",
			pluginDirectory: withPlugin,
			pluginConfig:    testPluginConfig("eu-central-1"),
			signedFor:       testPluginName,
			identity:        testPluginIdentity,
			expectedErr:     "trusted identify verification by plugin",
		},
		{
			name:         "no plugin directory configured",
			pluginConfig: region,
			signedFor:    testPluginName,
			identity:     testPluginIdentity,
			expectedErr:  "plugin unsupported",
		},
		{
			name:            "plugin not installed in the directory",
			pluginDirectory: withoutPlugin,
			pluginConfig:    region,
			signedFor:       testPluginName,
			identity:        testPluginIdentity,
			expectedErr:     "error while locating the verification plugin",
		},
		{
			name:            "signature needs another plugin",
			pluginDirectory: withPlugin,
			pluginConfig:    region,
			signedFor:       "another-plugin",
			identity:        testPluginIdentity,
			expectedErr:     "error while locating the verification plugin",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			v, err := newTestVerifier(test.pluginDirectory, test.pluginConfig, test.identity)
			if err != nil {
				t.Fatalf("failed to create verifier: %v", err)
			}
			result, err := v.Verify(context.Background(), signWithPluginAttributes(t, test.signedFor))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if test.expectedErr == "" {
				if result.Err != nil {
					t.Fatalf("expected the signature to verify, got: %v", result.Err)
				}
				return
			}
			if result.Err == nil {
				t.Fatalf("expected verification to fail with %q, but it succeeded", test.expectedErr)
			}
			if !strings.Contains(result.Err.Error(), test.expectedErr) {
				t.Fatalf("expected error containing %q, got: %v", test.expectedErr, result.Err)
			}
		})
	}
}

func TestNewVerifierPluginDirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name            string
		pluginDirectory string
		expectedErr     string
	}{
		{
			name:            "existing directory",
			pluginDirectory: t.TempDir(),
		},
		{
			name:            "missing directory",
			pluginDirectory: filepath.Join(t.TempDir(), "missing"),
			expectedErr:     "failed to access plugin directory",
		},
		{
			name:            "path is a file",
			pluginDirectory: file,
			expectedErr:     "is not a directory",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := newTestVerifier(test.pluginDirectory, nil, "*")
			if test.expectedErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.expectedErr) {
				t.Fatalf("expected error containing %q, got: %v", test.expectedErr, err)
			}
		})
	}
}
