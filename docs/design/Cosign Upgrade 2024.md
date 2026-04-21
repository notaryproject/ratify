# Cosign Upgrade 2024
Author: Akash Singhal (@akashsinghal)

Tracked issues in scope:
- [Support Cosign verification with multiple keys](https://github.com/notaryproject/ratify/issues/1191)
- [Support for Cosign verification with keys managed in KMS](https://github.com/notaryproject/ratify/issues/1190)
- [Support Cosign verification with RSA key](https://github.com/notaryproject/ratify/issues/1189)

Ratify currently supports keyless cosign verification which includes an optional custom Rekor server specification. Transparency log verification only occurs for keyless scenarios. Keyed verification is limited to a single public key specified as a value provided in the helm chart. The chart creates a `Secret` for the cosign key and mounts it at a well-known path in the Ratify container. Users must manually update the `Secret` to update the key. There is no support for multiple keys. There is no support for keys stored KMS. There is only support for ECDSA keys, and not RSA or ED25519. There is no support for certificates.

## Support key configuration as K8s resource

Currently, cosign verifier looks for a single key that already exists at a specified path in the Ratify container. Ratify helm chart contains a `Secret` which is mounted at the specified mount point. Ratify's key management experience should be decoupled from secrets and mount paths. Instead, it should be a first class key management experience similar to how certificates are managed via `CertificateStore`.

### User Experience

A new resource `KeyManagementProvider` will be introduced and the `CertificateStore` will be deprecated. `CertificateStore` will be maintained until Ratify v2.0.0. Only one resource type can be enabled at the same time. If a user attempts to apply the opposite type resource when one already exists for the opposing type, then a warning message will be shown in the Ratify logs.

Compared to the `CertificateStore`, the `KeyManagementProvider` (KMP) config spec will be updated to be more flexible. A new `name` field will be used only in CLI scenarios to mirror CRD name functionality as a unique identifier. This enables multiple KMP of same type to be used. The `type` field corresponds to the existing `provider` field in the `CertificateStore`.

Inline Key Management Provider with keys
```yaml
apiVersion: config.ratify.deislabs.io/v1beta1
kind: KeyManagementProvider
metadata:
  name: ratify-cosign-inline-key
  annotations:
    helm.sh/hook: pre-install,pre-upgrade
    helm.sh/hook-weight: "5"
spec:
  type: inline
  parameters:
    contentType: key
    value: |
    ---------- BEGIN RSA KEY ------------
    ******
    ---------- END RSA KEY ------------
    
```

Azure Key Vault KeyManagementProvider with keys
```yaml
apiVersion: config.ratify.deislabs.io/v1beta1
kind: KeyManagementProvider
metadata:
  name: kmp-akv
  annotations:
    helm.sh/hook: pre-install,pre-upgrade
    helm.sh/hook-weight: "5"
spec:
  type: azurekeyvault
  parameters:
    vaultURI: VAULT_URI
    keys:
      - name: KEY_NAME
        version: KEY_VERSION
    tenantID: TENANT_ID  
    clientID: CLIENT_ID
```

Azure Key Vault Key Management Provider with keys + certificates
```yaml
apiVersion: config.ratify.deislabs.io/v1beta1
kind: KeyManagementProvider
metadata:
  name: kmp-akv
  annotations:
    helm.sh/hook: pre-install,pre-upgrade
    helm.sh/hook-weight: "5"
spec:
  type: azurekeyvault
  parameters:
    vaultURI: VAULT_URI
    keys:
      - name: KEY_NAME
        version: KEY_VERSION
    certificates:
      - name: CERTIFICATE_NAME
        version: CERTIFICATE_VERSION
    tenantID: TENANT_ID  
    clientID: CLIENT_ID
```

CLI Config additions: The `keyManagementProviders` would be a new top level section in the `config.json`.
```json
{
  ...
  "keyManagementProviders": {
    {
      "name": "ratify-notation-inline-cert-kmprovider",
      "type": "inline",
      "contentType": "key",
      "value": "---------- BEGIN RSA KEY ------------
      ******
      ---------- END RSA KEY ------------"
    },
    {
      "name": "ratify-notation-inline-cert-kmprovider-2",
      "type": "inline",
      "contentType": "key",
      "value": "---------- BEGIN RSA KEY ------------
      ******
      ---------- END RSA KEY ------------"
    },
  }
  ...
}
```

### Implementation Details

- New API `GetKeys`
  - based on the existing `CertificateStore` API
  - return an a new map from `KMPMapKey` (`name` & `version`) to `PublicKey` which contains `crypto.PublicKey` & `ProviderType`. 
    - makes querying for keys by `name` and `version` much easier in cosign implementation
    - `ProviderType` is useful for special AKV consideration in cosign implementation.
- Global `Key`s map
  - follow same pattern as `Certificates` map which is updated on reconcile of the `CertificateStore` K8s resource.
  - how do we store the certificates so they are partioned by namespace, resource unique name, and optionally certificate/key name + version?
    - `Certificates` map will map `<namespace>/<name>` to a map of certificates for that particular resource
    - map will be keyed by a special struct `KMPMapKey` which contains a `Name` and `Version` field
    - each unique map key will map to a `PublicKey` which contains `crypto.PublicKey` and `ProviderType`.
    - Inline provider will store a single key mapped to a single map entry
    - AKV provider
      - If only certificate/key name provided. Fetch the latest version and only populate the `Name` field for the map key
      - If both name and version provided. Fetch specific version and populate both `Name` and `Version`. 
      - Note: A generic `Name` based fetched content will be considered uniquely different than a `Name` + `Version` content EVEN if the unversioned 'latest` is equal to a specified matching version.
- Cosign will be promoted to a built-in verifier and the plugin version will be removed
  - MUST maintain complete feature experience parity
  - Need to maintain legacy config and functionality
- Repurpose Inline Certificate Provider
  - add new `contentType` field to spec: "key" or "certificate". If not provided, default to "certificate" for backwards compatability. 
- Repurpose Azure Key Vault Certificate Provider
  - use `GetKeys` API to fetch keys from configured key vault
  - add new `keys` field to spec
- Multitenancy: supported by namespaced keys in the global `Keys` map

### How do we support CLI scenario?
  - CLI mode should support specification of a list of keys within the cosign verifier. Cosign plugin will handle directory configuration and key reading within implementation. Currently, one a single `key` path can be provided. This will be updated to support a `file` parameter in the trust Policy `keys` section (see trust policy details [here](#trust-policy)). The `provider` field is NOT required and is not allowed to be configured when the `file` is specified. For backward compatability, the existing `key` field will also be honored but that will default to previous legacy verification implementation.
    - example:
      ```json
      {
        ...
        "verifier": {
          "version": "1.0.0",
          "plugins": [
              {
                  "type": "cosign",
                  "name": "cosign-wabbit-networks",
                  "artifactTypes": "application/vnd.dev.cosign.artifact.sig.v1+json",
                  "trustPolicies": [
                    {
                      "name": "wabbit-networks-images",
                      "keys": [
                        {
                          "file": "/path/to/key1.pub"
                        },
                        {
                          "file": "/path/to/key2.pub"
                        }
                      ]
                    }
                  ]
              },
        }
        ...
      }    
      ```
  - `KeyManagementProvider` should be able to be configured via section in the `config.json`. This includes inline + any existing or future providers
  - The current AKV integration relies on workload identity. The CLI scenario will use a non-Workload Identity scheme for authentication to managed identity. The AzureKeyVault provider must be updated to support a generic `DefaultAzureCredential` which has built in keychain support for many different types of authentication schemes.

## Support Multiple keys for cosign verification

Currently, there is only support for a single key per cosign verifier. 

- Goals:
  - Cosign verifier should be updated to trust a set of keys and perform verification using that trusted key set
  - Cosign verifier MUST match the verification logic of Cosign CLI for a single Key
  - Cosign verifier should be able to operate a loose ('All keys are equally trusted and ONLY one is requred to be used in validation') or strict (ALL keys are trusted and ALL keys must be used in validation) enforcement.

### How does Cosign CLI verification work today?

- Image manifest pushed to same repository as subject (tag schema: `sha256-abc123.sig`)
- Image manifest is updated every time new signature is added. Each layer is a different signature (possibly from different signing keys)
```json
# Sample Cosign OCI Image Manifest
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "size": 451,
    "digest": "sha256:bbacdc3dc4b33c868c6c27192cb1d1bda619c1454abb57ebea806eac13250d3c"
  },
  "layers": [
    {
      "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json",
      "size": 254,
      "digest": "sha256:75a45fb043a8abfe52f256cb1a424d8808e886a3f40886228cdfa9b8d75c805d",
      "annotations": {
        "dev.cosignproject.cosign/signature": "MEQCIGoZazNt1/eEBc08AmcqXY+yNQQJY2ziZPiIopDjHnU5AiAUgeWBy90GgqDdnWpxd1b3lbqzgr2UV2ZyR59eDOyxVg=="
      }
    },
    {
      "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json",
      "size": 254,
      "digest": "sha256:75a45fb043a8abfe52f256cb1a424d8808e886a3f40886228cdfa9b8d75c805d",
      "annotations": {
        "dev.cosignproject.cosign/signature": "MEUCIBVcGGZR6pvJ2SQ8KI0TZY02SLFSSOFJuJph2Qcm8cWZAiEArL+BF5BGRGxELVBeJtAUy8i7L1uuBeUT9fF6TrFYVLQ="
      }
    },
    {
      "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json",
      "size": 254,
      "digest": "sha256:75a45fb043a8abfe52f256cb1a424d8808e886a3f40886228cdfa9b8d75c805d",
      "annotations": {
        "dev.cosignproject.cosign/signature": "MEQCIEIsK5yr1kGS1dgRmbudT55oghADdyAOfUwlnayPKAmmAiBTdZkhgHkZdw11tullz7HNOg5O1r5U/j4m2RE39b92Vg=="
      }
    }
  ]
}
```
- Image signature succeeds if AT LEAST one of the signatures verifies true with the corresponding key
  - Validation occurs on each signature in the manifest against the SAME key
  - Cosign only supports validation against a SINGLE key at a time

### Trust Policy
Cosign verifier should support multiple trust policies based on the KeyManagementProviders (KMP) enabled and the desired verification scenario. Please refer to [this](#user-scenarios) section for common user scenarios. At a high level users must be able to have:
  - multiple KMP `inline` key resources (each `inline` will have a single key)
  - multiple keys defined in a single AKV KMP
  - multiple KMP `inline` certificate resources (each `inline` may have a single cert or a cert chain)
  - multiple certificates definine in a single AKV KMP
  - mix of keys + certificates in a single AKV KMP
  - a way to specify specific keys/certificates within a KMP by name and version
  - a way to scope a trust policy to a particular registry/repo/image an wildcard characters '*'
  - multiple trust policies
  - a way to specify enforcement for that specific trust policy
    - skip: don't perform any verification for an image reference that matches this policy
    - any: at least one of the keys/certificates trusted in the policy must result in a successful verification for overall cosign verification to be true
    - all: ALL keys/certificates trusted in the policy must result in a successful verification for overall cosign verification to be true
  - a way to define certificates to be used in a trust policy for Trusted Timestamp verification `tsaCertificates`
  - a way to define options per trust policy for transparency log verification `tLogVerify`
  - a way to define options per trust policy for keyless verification under a section called `keyless`
    - certificate transparency log lookup `ctLogVerify`
    - `rekorURL` for custom rekor instances
    - `certificateIdentity`: certificate identity verifier should be configured to trust (OPTIONAL iff certificateIdentityExp is defined)
    - `certificateIdentityExp`: wildcard expressions mapping to certificate identitie(s) verifier should be configured to trust (OPTIONAL iff certificateIdentity is defined. Overrides certificateIdentity if also specified)
    - `certificateOIDCIssuer`: certificate OIDC Issuer verifier should be configured to trust (OPTIONAL iff certificateOIDCIssuerExp is defined)
    - `certificateOIDCIssuerExp`: wildcard expressions mapping to certificate OIDC Issuer(s) verifier should be configured to trust (OPTIONAL iff certificateOIDCIssuer is defined. Overrides certificateOIDCIssuer if also specified)
  - a way to scope the policy based on `artifactType` if we have nested verification `artifactTypeScopes`
    - if the user defines `artifactTypeScopes`, then the `scopes` are applied first and then `artifactTypeScopes`. `artifactTypeScopes` are only enforced if the subject image manifest being verified contains a `subject` field (basically is a referrer).
  - a way to specify local path keys using a `file` (Consider adding support for external URL and env variables to load file)

> NOTE: The sample below is an experience goal and not all configurations will be implemented initially

Sample
```yaml
apiVersion: config.ratify.deislabs.io/v1beta1
kind: Verifier
metadata:
  name: verifier-cosign
  annotations:
    helm.sh/hook: pre-install,pre-upgrade
    helm.sh/hook-weight: "5"
spec:
  name: cosign
  artifactTypes: application/vnd.dev.cosign.artifact.sig.v1+json
  parameters:
    trustPolicies:
      - name: wabbit-networks-images
        scopes:
          - wabbitnetworks.myregistry.io/carrots/*
          - wabbitnetworks.myregistry.io/beets/*
        artifactTypeScopes: # OPTIONAL: applied after scopes; only considered for nested verification scenarios. 
          - application/sarif+json
          - application/spdx+json
        keys: # list of keys that are trusted. Only the keys in KMS are considered
          - provider: inline-keys-1 # REQUIRED: if name is not provided, all keys are assumed to be trusted in KeyManagementProvider resource specified
          - provider: inline-keys-2
          - provider: akv-wabbit-networks
            name: wabbit-networks-io # OPTIONAL: key name (inline will not support name since each inline has only one key/certificate)
            version: 1234567890 # OPTIONAL: key version (inline will not support version)
          - file: /path/to/key.pub # absolute file path to local key path. Useful for CLI scenarios
        certificates: # list of certificates that are trusted. Only the certificates in KMS are considered
          - provider: nline-certs-1
        tsaCertificates:
          - provider: inline-certs-tsa-1
        tLogVerify: true # transparency log verification (default to false)
        keyless:
          ctLogVerify: false # certificate transparency log verification boolean (default to true)
          rekorURL: customrekor.io # rekor URL for transparency log verification (default to sigstore's public-good endpoint)
          certificateIdentity: wabbit-identity # certificate identity verifier should be configured to trust (OPTIONAL iff certificateIdentityExp is defined)
          certificateIdentityExp: # wildcard expressions mapping to certificate identitie(s) verifier should be configured to trust (OPTIONAL iff certificateIdentity is defined. Overrides certificateIdentity if also specified)
          certificateOIDCIssuer: wabbit-issuer # certificate OIDC Issuer verifier should be configured to trust (OPTIONAL iff certificateOIDCIssuerExp is defined)
          certificateOIDCIssuerExp: # wild card expressions mapping to certificate OIDC Issuer(s) verifier should be configured to trust (OPTIONAL iff certificateOIDCIssuer is defined. Overrides certificateOIDCIssuer if also specified)
        enforcement: any # skip (don't perform any verification and auto pass), any (at least one key/cert used in successfull verification is overall success), all (all keys/certs must be used for overall success)
      - name: verification-bypass
        scopes:
          - wabbitnetworks.myregistry.io/golden
        enforcement: skip
```

To start, support will include multiple `trustPolicies` with `keys` list specified. Each `key` entry can provider a `provider`, `name`, `version` OR a `file` path. Trust policies will support `scopes`. The behavior will match an equivalent `enforcement` of `any`. Future work will add support for remainig configs.

The `provider` field, where the name of the `KeyManagementProvider` (KMP) can be specified, is assumed to be referencing a `KMP` in the same namespace as the cosign verifier. If the user would like to specify a `provider` in a different namespace, the user must append `<namespace>/` to the front of the `KMP` name.

#### Scopes
The `scopes` section determines which trust policy will apply given an image reference. A global `*` wildcard character can be used as the default fallback of all other trust policies with `scopes` that do not match. Only a single trust policy can have a `*` scope. Wild card support is limited to suffix of a scope and denoted by '*' as the final character in the scope. Scopes with absolute or wild cards CANNOT overlap. On verifier creation, cosign will enforce that all scopes are deterministically exclusive. This is important so users cannot accidentally match multiple scopes depending on the image reference.

### User Scenarios

#### 1 Signature, 2 trusted keys
Bob has a container image he built. His trusted pool contains 2 self-managed keys to sign the image using `cosign`. Only ONE of the keys is used for signing at a time. There is only ONE signature. Bob's organization utilizes and trusts both keys. Bob wants to ensure all container images entering his K8s cluster are verified to have a valid cosign signature using AT LEAST one key from a trusted pool.

- Bob installs Ratify on the cluster
- Bob applies 2 new inline `KeyManagementProvider` CR onto the cluster, `inline-key-1` & `inline-key-2`. Each CR will have a key Bob's organization trusts.
```yaml
apiVersion: config.ratify.deislabs.io/v1alpha1
kind: KeyManagementProvider
metadata:
  name: inline-key-1
  annotations:
    helm.sh/hook: pre-install,pre-upgrade
    helm.sh/hook-weight: "5"
spec:
  type: inline
  parameters:
    contentType: key
    value: |
    ---------- BEGIN RSA KEY ------------
    ******
    ---------- END RSA KEY ------------
    
```
```yaml
apiVersion: config.ratify.deislabs.io/v1alpha1
kind: KeyManagementProvider
metadata:
  name: inline-key-2
  annotations:
    helm.sh/hook: pre-install,pre-upgrade
    helm.sh/hook-weight: "5"
spec:
  type: inline
  parameters:
    contentType: key
    value: |
    ---------- BEGIN RSA KEY ------------
    ******
    ---------- END RSA KEY ------------
    
```
- Bob applies the cosign verifier CR
```yaml
apiVersion: config.ratify.deislabs.io/v1beta1
kind: Verifier
metadata:
  name: verifier-cosign
  annotations:
    helm.sh/hook: pre-install,pre-upgrade
    helm.sh/hook-weight: "5"
spec:
  name: cosign
  artifactTypes: application/vnd.dev.cosign.artifact.sig.v1+json
  parameters:
    trustPolicies:
      - name: multiple-trusted-keys
        keys:
          - provider: inline-key-1
          - provider: inline-key-2
```
- Bob attempts to deploy a pod from an image that has cosign signature signed with key in KeyManagementProvider `inline-key-1`. Pod is verified and created successfully.
- Bob attempts to deploy a pod from an image that has cosign signature signed with key in KeyManagementProvider `inline-key-2`. Pod is verified and created successfully.
- Bob attempts to deploy a pod from an image that has cosign signature signed with key NOT in `inline-key-1` or `inline-key-2`. Pod FAILS verification and blocked.

#### 2 Signatures but only 1 is from a key that he trusts

Bob has a container image that he imported from another registry. An existing cosign signature, signed by an entity he doesn't trust, is already associated with the image. After vetting the image, he utilizes 1 self-managed key to sign the image using `cosign`. Now the image has 2 cosign signatures. Bob only trusts his key. Bob wants to ensure all container images entering his K8s cluster are verified to have a valid cosign signature using only HIS key that he trusts.

- Bob installs Ratify on the cluster
- Bob applies a new inline `KeyManagementProvider` CR onto the cluster, `inline-key`
```yaml
apiVersion: config.ratify.deislabs.io/v1alpha1
kind: KeyManagementProvider
metadata:
  name: inline-key
  annotations:
    helm.sh/hook: pre-install,pre-upgrade
    helm.sh/hook-weight: "5"
spec:
  type: inline
  parameters:
    contentType: key
    value: |
    ---------- BEGIN RSA KEY ------------
    ******
    ---------- END RSA KEY ------------
    
```

- Bob applies the cosign verifier CR
```yaml
apiVersion: config.ratify.deislabs.io/v1beta1
kind: Verifier
metadata:
  name: verifier-cosign
  annotations:
    helm.sh/hook: pre-install,pre-upgrade
    helm.sh/hook-weight: "5"
spec:
  name: cosign
  artifactTypes: application/vnd.dev.cosign.artifact.sig.v1+json
  parameters:
    trustPolicies:
      - name: single-trusted-key
        keys:
          - provider: inline-key
```
- Bob attempts to deploy a pod from the vetted image that has 2 cosign signatures, one of which is signed with key in KeyManagementProvider `inline-key`. Pod is verified and created successfully.
- Bob attempts to deploy a pod from an image that has cosign signature(s) signed with a different key in `inline-key`. Pod FAILS verification and blocked.

#### 2 Signatures 2 Keys: both keys must be used

Bob has a container image that is produced from a build pipeline and tested via a testing pipeline. After each pipeline, the image is signed with cosign using a SEPARATE key. Now the image has 2 cosign signatures. Bob trusts both keys and requires BOTH keys to be used. Bob wants to ensure all container images entering his K8s cluster are verified to have a valid cosign signature from his build AND test pipeline.

- Bob installs Ratify on the cluster
- Bob applies a new inline `KeyManagementProvider` CR onto the cluster, `inline-key-build` & `inline-key-test`
```yaml
apiVersion: config.ratify.deislabs.io/v1alpha1
kind: KeyManagementProvider
metadata:
  name: inline-key-build
  annotations:
    helm.sh/hook: pre-install,pre-upgrade
    helm.sh/hook-weight: "5"
spec:
  type: inline
  parameters:
    contentType: key
    value: |
    ---------- BEGIN RSA KEY ------------
    ******
    ---------- END RSA KEY ------------
    
```
```yaml
apiVersion: config.ratify.deislabs.io/v1alpha1
kind: KeyManagementProvider
metadata:
  name: inline-key-test
  annotations:
    helm.sh/hook: pre-install,pre-upgrade
    helm.sh/hook-weight: "5"
spec:
  provider: inline
  parameters:
    type: key
    value: |
    ---------- BEGIN RSA KEY ------------
    ******
    ---------- END RSA KEY ------------
    
```

- Bob applies the cosign verifier CR
```yaml
apiVersion: config.ratify.deislabs.io/v1beta1
kind: Verifier
metadata:
  name: verifier-cosign
  annotations:
    helm.sh/hook: pre-install,pre-upgrade
    helm.sh/hook-weight: "5"
spec:
  name: cosign
  artifactTypes: application/vnd.dev.cosign.artifact.sig.v1+json
  parameters:
    trustPolicies:
      - name: build-test-verification
        keys:
          - provider: inline-key-build
          - provider: inline-key-test
        enforcement: all
```
- Bob attempts to deploy a pod from the vetted image that has 1 cosign signature, which is signed with key in KeyManagementProvider `inline-key-build`. Pod FAILS verification and blocked.
- Bob attempts to deploy a pod from the vetted image that has 2 cosign signatures, which is signed with keys in KeyManagementProvider `inline-key-build` & `inline-key-test`. Pod passes verification and is created.

> **NOTE**: Based on Cosign's own verification implementation, there does not seem to be a way to enforce that ALL signatures found are valid. This behavior is unchartered as far as we can tell and would require Ratify to determine if we want to support this directly. For that reason, the strict ALL signature scenario is not yet included.

#### Extra Considerations
- How does Kyverno handle multiple Keys?
  - Each key specified is a separate cosign verification operation
  - User specifies enforcement type by specifying `count` of verification operations that must succeed.
    - e.g 2 keys specified and 2 signatures on the image. each verification is against both signatures for a single key
    - If count is 2, then 2 verifications must return true
- How will this work with OCI 1.1 enabled cosign?
  - Cosign OCI 1.1 support is experimental
  - Currently, an arbitrary signature from list of referrers is chosen to perform verifications on IF multiple cosign artifacts are found.
  - This logic will be updated in the future once 1.1 is GA but for now it's left as a TODO in the Cosign code base.

### Implementation Details

#### Handling multiple verifications at once
- Ratify will largely mirror how cosign performs multi-signature verification
  - cannot invoke cosign's multi signature verification API since the API exposed also includes the registry content fetch which is independent in Ratify

## Support RSA, EC, and ED25519 keys for verification

Each key specified will encapsulate a single verification context for all signatures found in the artifact that the verifier is running for.

Verification flow per key:
- Take raw key content (byte array) and [`LoadPublicKeyRaw()`](https://github.com/sigstore/cosign/blob/daf1eeb5ff2022d11466b8eccda25768b2dd2992/pkg/signature/keys.go#L91C1-L91C1)
- The `LoadPublicKeyRaw()` method in the cosign keys library will automatically detect which key type (based on the key header) and return the appropriate signature verifier
- Verifier is then passed to cosign's `VerifySignature()` method as a verification option

## Support keyless verification with OIDC identities
Newer versions of Cosign require that the user defines which identities and OIDC issuers they trust for keyless verifications. Ratify's Cosign verifier should `certificate-identity`, `certificate-identity-exp`, `certificate-oidc-issuer`, `certificate-oidc-issuer-regexp` to match Cosign cli behavior. The identity and issuer specification is REQUIRED and will be enforced during config validation.

### Implementation
- add 4 parameters to the `keyless` section of the trust policy config
- add new config validation logic to make sure at least the issuer & identity is defined or accompanying regexp
- pass through issuer & identity parameters as options to the cosign verifier `VerifyImage` function.

## Dev Work Items
- Introduce new `KeyManagementProvider` CRD to replace `CertificateStore` (~ 2 weeks)
  - maintain old `CertificateStore` controllers and source code for backwards compat
  - define new `KeyManagementProvider` CRD + controllers
  - port certificate providers implementation to new `KMP` object
  - refactor to factory paradigm
  - refactor to define rigid config schema (currently, only a generic map of attributes passed)
  - add enforcement so only `KeyManagementProvider` OR `CertificateStore` can be enabled at a time
  - add id support for certificates in the global `Certificates` map
- Add Key support to `KeyManagementProvider` (~ 2-3 weeks)
  - update API
  - update Inline provider with `type` field
  - update AKV provider for `key` fetching logic
  - update controllers to add new key maps for global + namespaced keys
  - update controllers to add new certs maps for namespaced certs
- Cosign Verifier: migrate to a built in verifier (~ 1-2 weeks)
- Cosign verifier multi key support (~ 3 weeks)
  - add `trustPolicies`
    - support multiple `keys` each with `provider`, and optional `name`, `version`
    - support `scopes`
  - add multi key verification logic
  - preserve existing file path based key support for backwards compatability
- Add more robust Cosign Keyless support (~1.5 weeks)
  - add new section to Trust Policy
  - add support for Trust policy to use keyless vs key when both are specified?
  - add new support for `ctLogVerify` configuration
- Add RSA and ED25519 key support (~ 0.5 week)
  - auto detect key type based on parsing library
  - pick cosign verifier according to format
- Add docs and walkthroughs (~ 1 week)
  - redo cosign walk through
  - update all walkthroughs and samples to use `KeyManagementProvider`
  - add reference docs for `KeyManagementProvider`
  - mark `CertificateStore` docs as deprecated
- New e2e tests for different scenarios (~ 1 week)

## Future Considerations
- Add `KeyManagementProvider` support to CLI
  - Update  `verify` command group to create `KeyManagementProvider` from config
  - Update AKV provider for non Workload Identity auth
- Add Plugin support to `KeyManagementProvider`
- Add deprecation headers and warnings to `CertificateStore` CRD and code files
- Support `enforcement` with `skip`, `any`, and `all`
- Support attestations with cosign signature embedded
- Support certificate based verification of cosign signatures
- Verify image annotations
- Custom signature repository
- Transparency log and SCT verification options
- Keyless signature verification options
  - Custom Rekor server
  - Github workflows