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

package authprovider

import (
	"context"
	"errors"
	"testing"

	ratifyerrors "github.com/notaryproject/ratify/v2/errors"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// TestResolveCredentialFromSecret_K8SecretDockerConfigJson_ReturnsExpected checks
// K8s Docker Json Config Secret is properly extracted and credentials returned when Provide is called
func TestResolveCredentialFromSecret_K8SecretDockerConfigJson_ReturnsExpected(t *testing.T) {
	var testSecret core.Secret
	testSecret.Data = make(map[string][]byte)
	testSecret.Data[core.DockerConfigJsonKey] = []byte(secretContent)
	testSecret.Type = core.SecretTypeDockerConfigJson

	var k8secretprovider k8SecretAuthProvider

	authConfig, err := k8secretprovider.resolveCredentialFromSecret(context.Background(), "index.docker.io", &testSecret)
	if err != nil {
		t.Fatalf("resolveCredentialFromSecret failed to get credential with err %v", err)
	}

	if authConfig.Username != testUserName || authConfig.Password != testPassword {
		t.Fatalf("resolveCredentialFromSecret returned incorrect credentials (username: %s, password: %s)", authConfig.Username, authConfig.Password)
	}
}

// TestResolveCredentialFromSecret_K8SecretDockerConfigJsonWithIdentityToken_ReturnsExpected checks
// K8s Docker Json Config Secret is properly extracted and credentials returned when Provide is called with an identity token
func TestResolveCredentialFromSecret_K8SecretDockerConfigJsonWithIdentityToken_ReturnsExpected(t *testing.T) {
	var testSecret core.Secret
	testSecret.Data = make(map[string][]byte)
	testSecret.Data[core.DockerConfigJsonKey] = []byte(secretContentIdentityToken)
	testSecret.Type = core.SecretTypeDockerConfigJson

	var k8secretprovider k8SecretAuthProvider

	authConfig, err := k8secretprovider.resolveCredentialFromSecret(context.Background(), "index.docker.io", &testSecret)
	if err != nil {
		t.Fatalf("resolveCredentialFromSecret failed to get credential with err %v", err)
	}

	if authConfig.Username != dockerTokenLoginUsernameGUID || authConfig.IdentityToken != identityTokenOpaque {
		t.Fatalf("resolveCredentialFromSecret returned incorrect credentials (username: %s, identitytoken: %s)", authConfig.Username, authConfig.IdentityToken)
	}
}

// Checks an error is returned for non-existent registry credential
func TestResolveCredentialFromSecret_K8SecretNonExistentRegistry_ReturnsExpected(t *testing.T) {
	var testSecret core.Secret
	testSecret.Data = make(map[string][]byte)
	testSecret.Data[core.DockerConfigJsonKey] = []byte(secretContent)
	testSecret.Type = core.SecretTypeDockerConfigJson

	var k8secretprovider k8SecretAuthProvider

	if _, err := k8secretprovider.resolveCredentialFromSecret(context.Background(), "nonexistent.ghcr.io", &testSecret); !errors.Is(err, ratifyerrors.ErrorCodeNoMatchingCredential) {
		t.Fatalf("resolveCredentialFromSecret should have failed to get credential with err %v but returned err %v", ratifyerrors.ErrorCodeNoMatchingCredential, err)
	}
}

// TestProvide_NotEnabled_ReturnsExpected tests that the Provide method
// returns an error when the k8SecretAuthProvider is not enabled
func TestProvide_NotEnabled_ReturnsExpected(t *testing.T) {
	var k8secretprovider k8SecretAuthProvider

	if _, err := k8secretprovider.Provide(context.Background(), "nonexistent.ghcr.io/artifact:v1"); err == nil {
		t.Fatalf("Provide should have failed to get credential with err but returned nil")
	}
}

// TestProvide_InvalidHostName_ReturnsExpected tests that the Provide method
// returns an error when the hostname is invalid
func TestProvide_InvalidHostName_ReturnsExpected(t *testing.T) {
	k8secretprovider := k8SecretAuthProvider{
		ratifyNamespace:  "gatekeeper-system",
		clusterClientSet: fake.NewSimpleClientset(),
	}

	if _, err := k8secretprovider.Provide(context.Background(), "badhostname/artifact:v1"); err == nil {
		t.Fatalf("Provide should have failed to get credential with err but returned nil")
	}
}

// TestProvide_SecretNotFound_ReturnsExpected tests that the Provide method
// returns an error when the secret is not found
func TestProvider_SecretNotFound_ReturnsExpected(t *testing.T) {
	k8secretprovider := k8SecretAuthProvider{
		ratifyNamespace: "gatekeeper-system",
		clusterClientSet: fake.NewSimpleClientset(&core.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "non-matching-secret",
				Namespace: "gatekeeper-system",
			},
		}),
		config: k8SecretAuthProviderConf{
			Secrets: []secretConfig{
				{
					SecretName: "test-secret",
				},
			},
		},
	}

	if _, err := k8secretprovider.Provide(context.Background(), "ghcr.io/artifact:v1"); err == nil {
		t.Fatalf("Provide should have failed to get credential with err but returned nil")
	}
}

// TestProvide_SecretIncorrectType_ReturnsExpected tests that the Provide method
// returns an error when the secret type is incorrect
func TestProvider_IncorrectSecretType_ReturnsExpected(t *testing.T) {
	k8secretprovider := k8SecretAuthProvider{
		ratifyNamespace: "gatekeeper-system",
		clusterClientSet: fake.NewSimpleClientset(&core.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-secret",
				Namespace: "gatekeeper-system",
			},
			Type: core.SecretTypeBasicAuth,
		}),
		config: k8SecretAuthProviderConf{
			Secrets: []secretConfig{
				{
					SecretName: "test-secret",
				},
			},
		},
	}

	if _, err := k8secretprovider.Provide(context.Background(), "ghcr.io/artifact:v1"); err == nil {
		t.Fatalf("Provide should have failed to get credential with err but returned nil")
	}
}

// TestProvide_NoMatchingCredential_ReturnsExpected tests that the Provide method
// returns an error when no matching credential is found
func TestProvider_NoMatchingCredential_ReturnsExpected(t *testing.T) {
	k8secretprovider := k8SecretAuthProvider{
		ratifyNamespace: "gatekeeper-system",
		clusterClientSet: fake.NewSimpleClientset(&core.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-secret",
				Namespace: "gatekeeper-system",
			},
			Type: core.SecretTypeDockerConfigJson,
			Data: map[string][]byte{
				core.DockerConfigJsonKey: []byte(secretContent),
			},
		}),
		config: k8SecretAuthProviderConf{
			Secrets: []secretConfig{
				{
					SecretName: "test-secret",
				},
			},
		},
	}

	if _, err := k8secretprovider.Provide(context.Background(), "ghcr.io/artifact:v1"); err == nil {
		t.Fatalf("Provide should have failed to get credential with err but returned nil")
	}
}

// TestProvide_ServiceAccountNotFound_ReturnsExpected tests that the Provide method
// returns an error when the service account has no image pull secrets
func TestProvider_ServiceAccountNoSecrets_ReturnsExpected(t *testing.T) {
	k8secretprovider := k8SecretAuthProvider{
		ratifyNamespace: "gatekeeper-system",
		clusterClientSet: fake.NewSimpleClientset(&core.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ratify-admin",
				Namespace: "gatekeeper-system",
			},
		}),
		config: k8SecretAuthProviderConf{
			ServiceAccountName: "ratify-admin",
		},
	}

	if _, err := k8secretprovider.Provide(context.Background(), "ghcr.io/artifact:v1"); err == nil {
		t.Fatalf("Provide should have failed to get credential with err but returned nil")
	}
}

// TestProvide_ServiceAccountSecretNotFound_ReturnsExpected tests that the Provide method
// returns an error when the service account refers to a secret that does not exist
func TestProvider_ServiceAccountSecretNotFound_ReturnsExpected(t *testing.T) {
	k8secretprovider := k8SecretAuthProvider{
		ratifyNamespace: "gatekeeper-system",
		clusterClientSet: fake.NewSimpleClientset(&core.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ratify-admin",
				Namespace: "gatekeeper-system",
			},
			ImagePullSecrets: []core.LocalObjectReference{
				{
					Name: "non-existent-secret",
				},
			},
		}),
		config: k8SecretAuthProviderConf{
			ServiceAccountName: "ratify-admin",
		},
	}

	if _, err := k8secretprovider.Provide(context.Background(), "ghcr.io/artifact:v1"); err == nil {
		t.Fatalf("Provide should have failed to get credential with err but returned nil")
	}
}

// TestProvide_ServiceAccountSecretIncorrectType_ReturnsExpected tests that the Provide method
// returns an error when the service account refers to a secret with an incorrect type
func TestProvider_ServiceAccountSecretIncorrectType_ReturnsExpected(t *testing.T) {
	k8secretprovider := k8SecretAuthProvider{
		ratifyNamespace: "gatekeeper-system",
		clusterClientSet: fake.NewSimpleClientset(&core.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ratify-admin",
				Namespace: "gatekeeper-system",
			},
			ImagePullSecrets: []core.LocalObjectReference{
				{
					Name: "test-secret",
				},
			},
		}, &core.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-secret",
				Namespace: "gatekeeper-system",
			},
			Type: core.SecretTypeBasicAuth,
		}),
		config: k8SecretAuthProviderConf{
			ServiceAccountName: "ratify-admin",
		},
	}

	if _, err := k8secretprovider.Provide(context.Background(), "ghcr.io/artifact:v1"); err == nil {
		t.Fatalf("Provide should have failed to get credential with err but returned nil")
	}
}

// TestProvide_ServiceAccountNoMatchingCredential_ReturnsExpected tests that the Provide method
// returns an error when no matching credential is found for any of the service account image pull secrets
func TestProvider_ServiceAccountNoMatchingCredential_ReturnsExpected(t *testing.T) {
	k8secretprovider := k8SecretAuthProvider{
		ratifyNamespace: "gatekeeper-system",
		clusterClientSet: fake.NewSimpleClientset(&core.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ratify-admin",
				Namespace: "gatekeeper-system",
			},
			ImagePullSecrets: []core.LocalObjectReference{
				{
					Name: "test-secret",
				},
			},
		}, &core.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-secret",
				Namespace: "gatekeeper-system",
			},
			Type: core.SecretTypeDockerConfigJson,
			Data: map[string][]byte{
				core.DockerConfigJsonKey: []byte(secretContent),
			},
		}),
		config: k8SecretAuthProviderConf{
			ServiceAccountName: "ratify-admin",
		},
	}

	if _, err := k8secretprovider.Provide(context.Background(), "ghcr.io/artifact:v1"); err == nil {
		t.Fatalf("Provide should have failed to get credential with err but returned nil")
	}
}

// TestProvide_ServiceAccountSecretFound_ReturnsSuccess tests that the Provide method
// returns auth config when a matching credential is found for a user defined secret
func TestProvider_SecretFound_ReturnsSuccess(t *testing.T) {
	k8secretprovider := k8SecretAuthProvider{
		ratifyNamespace: "gatekeeper-system",
		clusterClientSet: fake.NewSimpleClientset(&core.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-secret",
				Namespace: "gatekeeper-system",
			},
			Type: core.SecretTypeDockerConfigJson,
			Data: map[string][]byte{
				core.DockerConfigJsonKey: []byte(secretContent),
			},
		}),
		config: k8SecretAuthProviderConf{
			Secrets: []secretConfig{
				{
					SecretName: "test-secret",
				},
			},
		},
	}

	if _, err := k8secretprovider.Provide(context.Background(), "index.docker.io/artifact:v1"); err != nil {
		t.Fatalf("Provide failed to get credential with err %v", err)
	}
}

// TestProvide_ServiceAccountSecretFound_ReturnsSuccess tests that the Provide method
// returns auth config when a matching credential is found for a service account image pull secret
func TestProvider_ServiceAccountSecretFound_ReturnsSuccess(t *testing.T) {
	k8secretprovider := k8SecretAuthProvider{
		ratifyNamespace: "gatekeeper-system",
		clusterClientSet: fake.NewSimpleClientset(&core.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ratify-admin",
				Namespace: "gatekeeper-system",
			},
			ImagePullSecrets: []core.LocalObjectReference{
				{
					Name: "test-secret",
				},
			},
		}, &core.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-secret",
				Namespace: "gatekeeper-system",
			},
			Type: core.SecretTypeDockerConfigJson,
			Data: map[string][]byte{
				core.DockerConfigJsonKey: []byte(secretContent),
			},
		}),
		config: k8SecretAuthProviderConf{
			ServiceAccountName: "ratify-admin",
		},
	}

	if _, err := k8secretprovider.Provide(context.Background(), "index.docker.io/artifact:v1"); err != nil {
		t.Fatalf("Provide failed to get credential with err %v", err)
	}
}
