# Ratify Helm Chart

## Get Repo Info

```console
helm repo add ratify https://notaryproject.github.io/ratify
helm repo update
```

_See [helm repo](https://helm.sh/docs/helm/helm_repo/) for command documentation._

## Install Chart

```console
# Helm install with gatekeeper-system namespace already created
$ helm install [RELEASE_NAME] ratify/ratify-gatekeeper-provider --atomic --namespace gatekeeper-system --set image.tag=<RELEASE_TAG>

# Helm install and create namespace
$ helm install [RELEASE_NAME] ratify/ratify-gatekeeper-provider --atomic --namespace gatekeeper-system --create-namespace --set image.tag=<RELEASE_TAG>
```

_See [parameters](#parameters) below._

_See [helm install](https://helm.sh/docs/helm/helm_install/) for command documentation._

## Upgrade Chart

```console
$ helm upgrade -n gatekeeper-system [RELEASE_NAME] ratify/ratify-gatekeeper-provider --set image.tag=<RELEASE_TAG>
```

## Deprecation Policy

Values marked `# DEPRECATED` in the `values.yaml` as well as **DEPRECATED** in the below parameters will NOT be supported in the next major version release. Existing functionality will remain backwards compatible until the next major version release.

## Parameters
| Parameter                                 | Description                                                                                                                                                                                                                                  | Default                                         |
|--------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------|
| `image.repository`                        | Ratify app image                                                                                                                                                                                                                            | `ghcr.io/notaryproject/ratify-gatekeeper-provider` |
| `image.tag`                               | Image tag                                                                                                                                                                                                                                   | `<INSERT THE LATEST RELEASE TAG>`               |
| `image.pullPolicy`                        | Image pull policy                                                                                                                                                                                                                           | `IfNotPresent`                                  |
| `replicaCount`                            | Number of replicas to run                                                                                                                                                                                                                   | `1`                                             |
| `notation.scopes`                         | Scopes that Notation verifier is applicable for. See [Notation trust policy](https://github.com/notaryproject/specifications/blob/main/specs/trust-store-trust-policy.md#trust-policy).                 | `[]`                                            |
| `notation.trustedIdentities`              | List of trusted identities for Notation verifier. See [Notation trust policy](https://github.com/notaryproject/specifications/blob/main/specs/trust-store-trust-policy.md#trust-policy).                | `[]`                                            |
| `notation.certs`                          | List of trusted root certificates for Notation verifier.                                                                                                                                              | `[]`                                            |
| `stores[0].scopes`                        | Scopes that the store is applicable for. If it's not set, it will be overridden by the executor's scopes.                                                                                                                                                             | `[]`                                            |
| `stores[0].username`                      | Username to authenticate to the store.                                                                                                                                                               | `""`                                            |
| `executor.scopes`                         | Scopes that the executor is applicable for. And it MUST NOT be empty for the executor to be valid.                                                                                                                                                              | `[]`                                            |
| `executor.concurrency`                    | The maximum number of concurrent execution per validation request.                                                                                                                                  | `3`                                            |
| `stores[0].password`                      | Password to authenticate to the store.                                                                                                                                                               | `""`                                            |
| `provider.tls.crt`                        | Ratify Gatekeeper Provider's TLS public certificate.                                                                                                                                                 | `""`                                            |
| `provider.tls.key`                        | Ratify Gatekeeper Provider's TLS private key.                                                                                                                                                        | `""`                                            |
| `provider.tls.caCert`                     | CA certificate to verify the TLS certificate.                                                                                                                                                        | `""`                                            |
| `provider.tls.disableCertRotation`        | Disable automatic TLS certificate rotation. When cert rotation is enabled, tls.crt, tls.key and tls.caCert are not required.                                                                         | `false`                                         |
| `provider.disableCRDManager`              | Disable CRD manager to manage the executor CRDs. This is useful when you want to configure executors through mounted config.json.                                                                | `false`                                         |
| `provider.disableMutation`                | Enables/disables tag-to-digest mutation for all admission resource creations. It is highly recommended to enable mutation since the verified digest may be different from the one run.                | `false`                                         |
| `provider.timeout.validationTimeoutSeconds`| Verify request handler timeout in seconds. This MUST match the configured Gatekeeper `validatingWebhookTimeoutSeconds`.                                                                              | `5`                                             |
| `provider.timeout.mutationTimeoutSeconds` | Mutate request handler timeout in seconds. This MUST match the configured Gatekeeper `mutatingWebhookTimeoutSeconds`.                                                                                | `2`                                             |
| `gatekeeper.namespace`                    | Namespace where Gatekeeper is installed. This MUST match the configured Gatekeeper `namespace`.                                                                                                      | `gatekeeper-system`                             |
| `serviceAccount.create`                   | Create new dedicated Ratify service account                                                                                                                                                          | `true`                                          |
| `serviceAccount.name`                     | Name of Ratify Gatekeeper Provider service account to create                                                                                                                                         | `ratify-gatekeeper-provider-admin`              |
| `serviceAccount.annotations`              | Annotations to add to the service account                                                                                                                                                            | `{}`                                            |
| `cosign.scopes` | Scopes that Cosign verifier is applicable for. If it's not set, it will be overridden by the executor's scopes.                                                                                                                              | `[]`                                            |
| `cosign.certificateIdentity`              | The expected certificate identity in the Cosign signature. |                                                                                                                                               | `""`                                            |
| `cosign.certificateIdentityRegex`       | The expected certificate identity Regex in the Cosign signature. |                                                                                                                                               | `""`                                            |
| `cosign.certificateOIDCIssuer`              | The expected OIDC issuer in the Cosign signature. |                                                                                                                                               | `""`                                            |
| `cosign.certificateOIDCIssuerRegex`       | The expected OIDC issuer Regex in the Cosign signature. |                                                                                                                                               | `""`                                            |
| `cosign.ignoreTLog`                     | Whether to ignore transparency log verification in Cosign verifier.                                                                                                                                   | `false`                                         |
| `cosign.ignoreCTLog`                    | Whether to ignore certificate transparency log verification in Cosign verifier.                                                                                                                              | `false`                                         |
| `cosign.keys.provider`                    | The provider type of the public keys. Supported values include `inline`, `azure`.                                                                                                                                         | `inline`                                        |
| `cosign.keys.key`                         | The public keys used to verify the Cosign signature. This field is required when `cosign.keys.provider` is `inline`.                                                                                                                | `""`                                            |