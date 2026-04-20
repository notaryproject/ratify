# Cosign Upgrade 2024
Author: Akash Singhal (@akashsinghal)

Tracked issues in scope:
- [Support Cosign verification with multiple keys](https://github.com/notaryproject/ratify/issues/1191)
- [Support for Cosign verification with keys managed in KMS](https://github.com/notaryproject/ratify/issues/1190)
- [Support Cosign verification with RSA key](https://github.com/notaryproject/ratify/issues/1189)
- [Support keyless verification with OIDC identities](https://github.com/notaryproject/ratify/issues/1323)

Ratify currently supports keyless cosign verification which includes an optional custom Rekor server specification. Transparency log verification only occurs for keyless scenarios. Keyed verification is limited to a single public key specified as a value provided in the helm chart. The chart creates a `Secret` for the cosign key and mounts it at a well-known path in the Ratify container. Users must manually update the `Secret` to update the key. There is no support for multiple keys. There is no support for keys stored KMS. There is only support for ECDSA keys, and not RSA or ED25519. There is no support for certificates.

## Support key configuration as K8s resource

Currently, cosign verifier looks for a single key that already exists at a specified path in the Ratify container. Ratify helm chart contains a `Secret` which is mounted at the specified mount point. Ratify's key management experience should be decoupled from secrets and mount paths. Instead, it should be a first class key management experience similar to how certificates are managed via `CertificateStore`.

### Option 1: Extend existing Certificate Store

#### User Experience

Inline certificate provider with key
```yaml
apiVersion: config.ratify.deislabs.io/v1beta1
kind: CertificateStore
metadata:
  name: ratify-cosign-inline-key
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

Azure Key Vault certificate provider with keys
```yaml
apiVersion: config.ratify.deislabs.io/v1beta1
kind: CertificateStore
metadata:
  name: certstore-akv
  annotations:
    helm.sh/hook: pre-install,pre-upgrade
    helm.sh/hook-weight: "5"
spec:
  provider: azurekeyvault
  parameters:
    vaultURI: VAULT_URI
    keys:
      - name: KEY_NAME
        version: KEY_VERSION
    tenantID: TENANT_ID  
    clientID: CLIENT_ID
```

Azure Key Vault certificate provider with keys + certificates
```yaml
apiVersion: config.ratify.deislabs.io/v1beta1
kind: CertificateStore
metadata:
  name: certstore-akv
  annotations:
    helm.sh/hook: pre-install,pre-upgrade
    helm.sh/hook-weight: "5"
spec:
  provider: azurekeyvault
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
#### Implementation Details

- New API `GetKeys`
  - added to the `CertificateStore` API
  - return an array of `Key`s. 
    - contains `byte` array content
- Global `Key`s map
  - follow same pattern as `Certificates` map which is updated on reconcile of the `CertificateStore` K8s resource.
  - how do we store the certificates so they are partioned by namespace, resource unique name, and optionally certificate/key name + version?
    - `Certificates` map will map `<namespace>/<name>` to a map of certificates for that particular resource
    - map will be keyed by a special struct `KMPMapKey` which contains a `Name` and `Version` field
    - each unique map key will map to an array x.509 certificates
    - Inline provider will store all certs in a single map entry
    - AKV provider
      - If only certificate/key name provided. Fetch the latest version and only populate the `Name` field for the map key
      - If both name and version provided. Fetch specific version and populate both `Name` and `Version`. 
      - Note: A generic `Name` based fetched content will be considered uniquely different than a `Name` + `Version` content EVEN if the unversioned 'latest` is equal to a specified matching version. 
- Can we promote Cosign to be a built-in verifier like Notation is?
  - This would allow us to use `CertificateStore` without having to build support for external plugins accessing certificates.
  - It will also be slightly more performant if it can share the in-memory ORAS store cache.
  - **UPDATE 1/18/24: Cosign verifier will be built-in**
- ~~How do we share certificates and keys with external plugins?~~
  - ~~All certs are loaded in an in-memory map currently. The map cannot be shared with external processes.~~
  - ~~External plugins should NOT be pulling certificates/keys per invocation (external KMS would be stressed. result in very expensive calls)~~
  - ~~Option 1: Serialize and add `Certificates` & `Keys` map into the external plugin json input~~
    - ~~Embed each map during plugin invocation~~
      - ~~namespace context aware for multi-tenancy~~
      - ~~Is security a concern for embedding certs + keys to invoke plugins not related to signature verification?~~
    - ~~Cosign verifier will be updated to deserialize and consume the maps~~
  - ~~Option 2: Store certs + keys on disk at well-known path~~
    -  ~~`CertificateStore` will be refactored to store fetched certs from providers in a directory on disk~~
      ```diff
      - .ratify/certificate_store/
      - <provider_name>-<namespace>/
      -   keys/
      -     key1.rsa
      -   certificates/
      -     cert1.pem
      -     cert2.pem
      ```
    - ~~Configuration loading from JSON (CLI) or CRD reconcile loop will be responsible for deleting the directories of cert providers as they are removed~~
    - ~~External plugins will have to have the `CertificateStore` config passed in as JSON input in order to create instance of the cert provider objects~~
    - ~~External plugins will need to be namespace aware in order to know which directory to access~~
    - ~~Pros:~~
      - ~~Cosign plugin can manage accessing its own keys + certificates without executor having to coordinate~~
      - ~~Other external plugins will not get unnecessary keys + certs provided in json input~~ 
    - ~~Cons:~~
      - ~~Keys + certs must be added/deleted off disk~~
        - ~~What happens if keys + certs are left on disk due to Ratify failure?~~
        - ~~Keys + certs will be able to be accessed by any process with filesystem access~~
        - ~~CLI scenario will require fetching + deleting certs + keys off disk per invocation~~
      - ~~Existing cert providers used by notation will need to be updated to read/write certs from disk~~
      - ~~External plugins will need to be aware of namespace context in order to only access resources in namespaced directory~~
  - ~~Option 3 (NOT recommended): Add certificates + keys to shared cache~~
    - ~~Define two new cache keys partitioned by namespace~~
    - ~~CANNOT use the ristretto in-memory cache as it is since external cosign process must be able to access it~~
      - ~~This would require hard dependency on HA mode which is a bad experience. Why should a user need HA distributed cache just for Cosign?~~
      - ~~Implement a new cache provider for cache sharing between processes on same host~~
        - ~~NOT trivial~~
        - ~~Require a new http cache server and clients~~
    - ~~Cache provider initialization in cosign plugin implementation~~
    - ~~One advantage is that not only will cert + key sharing be solved but also oras store credentials can easily shared which is currently not possible for external plugins~~
- Extend Inline Certificate Provider
  - add new `type` field to spec: "key" or "certificate". If not provided, default to "certificate" for backwards compatability. 
- Extend Azure Key Vault Certificate Provider
  - use `GetKeys` API to fetch keys from configured key vault
  - add new `keys` field to spec
- Multitenancy considerations
  - Need a separate keys map for namespaced and global certificate store keys

### **Option 2: Renaming CertificateStore to KeyManagementProvider** SELECTED IMPLEMENTATION
- Same as Option 1 except we introduce a new CRD that will replace `CertificateStore` due to potential naming confusion
- Is the existing name confusing enough to warrant changing to KeyManagementProvider?
- How would we support CRD name change?
  - Introduce new `KeyManagementProvider` CRD resource and then deprecate `CertificateStore`

#### Proposed Config Changes

Compared to the `CertificateStore`, the `KeyManagementProvider` config spec could be updated to be more flexible. A new `name`` field will be used only in CLI scenarios to mirror CRD name functionality as a unique identifier. This enables multiple KMS of same type to be used.

```yaml
apiVersion: config.ratify.deislabs.io/v1beta1
kind: KeyManagementProvider
metadata:
  name: ratify-notation-inline-cert-kmprovider
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

CLI Config additions: The `keyManagementSystems` would be a new top level section in the `config.json`.
```json
{
  ...
  "keyManagementSystems": {
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

**Do we want to consider making the inline provider accept an array of content?**

### Option 3: Introduce new CRD `KeyStore` separate from `CertificateStore`

All of the same considerations as Option 1. It will be a completely new CRD with an inline and AKV provider equivalent.

Pros: 
- More intuitive naming: embedding 'key' specification in cert store might be confusing
- No breaking changes or backwards compatability requirements
Cons:
- Yet one more resource type user must be concerned to configure
- Providers will share almost the exact same implementation as certificate stores

### How do we support CLI scenario?
  - CLI mode should support specification of a list of keys within the cosign verifier. Cosign plugin will handle directory configuration and key reading within implementation. Currently, one a single `key` path can be provided. This will be updated to support an absolute `filePath` to a key per entry in the `keys` field of the Cosign trust policy (see trust policy details [here](#trust-policy)). The `provider` field is NOT required and is ignored if provided when the `filePath` is specified. For backward compatability, the existing `key` field will also be honored.
    - example `config.json`:
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
                          "filePath": "/path/to/key1.pub"
                        },
                        {
                          "filePath": "/path/to/key2.pub"
                        }
                      ]
                    }
                  ]
              },
        }
        ...
      }    
      ```
  - Should we have a separate local directory cert store provider that gets configured like other cert stores or should we scope it only to the cosign plugin?
    - In K8s scenarios, it will not be an encouraged pattern to specify local directory. This is why implementing directory cert reading as a cert store provider may not make  sense.
    - However, if a user decides to do a mixture of cert stores + local directory then they would need to specify in 2 different sections (cosign plugin config + cert store)
    - **UPDATE 3/11/24**: We will provide a local `filePath` for configuring local public keys
  - The current AKV integration relies on workload identity. The CLI scenario will use a non-WI scheme for authentication to managed identity

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
  - Validation occurs on each signature in the manifest in parallel against the SAME key
  - Cosign only supports validation against a SINGLE key at a time

### Trust Policy
Cosign verifier should support multiple trust policies based on the KeyManagementProviders (KMP) enabled and the desired verification scenario. Please refer to [this](#user-scenarios) section for common user scenarios. At a high level users must be able to have:
  - multiple KMP `inline` key resources (each `inline` will have a single key)
  - multiple keys defined in a single AKV KMP
  - multiple KMP `inline` certificate resources (each `inline` may have a single cert or a cert chain)
  - multiple certificates definine in a single AKV KMP
  - mix of keys + certificates in a single AKV KMP
  - a way to specify specific keys/certificates within a KMP by name and version
  - a way to specify specific AKV keys/certificate by `Certificate ID` or `Key ID` URL.
  - a way to scope a trust policy to a particular registry/repo/image
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
  -  a way to specify local path keys using a `filePath`

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
          - wabbitnetworks.myregistry.io/carrots
          - wabbitnetworks.myregistry.io/beets
        artifactTypeScopes: # OPTIONAL: applied after scopes; only considered for nested verification scenarios. 
          - application/sarif+json
          - application/spdx+json
        keys: # list of keys that are trusted. Only the keys in KMS are considered
          - provider: inline/inline-keys-1 # REQUIRED: if name is not provided, all keys are assumed to be trusted in KeyManagementProvider resource specified
          - provider: inline/inline-keys-2
          - provider: azurekeyvault/akv-wabbit-networks
            name: wabbit-networks-io # OPTIONAL: key name (inline will not support name since each inline has only one key/certificate)
            version: 1234567890 # OPTIONAL: key version (inline will not support version)
          - provider: wabbit-local-key # REQUIRED: can be any name if filePath is specified
            filePath: /path/to/key.pub # absolute file path to local key path. Useful for CLI scenarios
        certificates: # list of certificates that are trusted. Only the certificates in KMS are considered
          - provider: inline/inline-certs-1
        tsaCertificates:
          - provider: inline/inline-certs-tsa-1
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

To start, only a single `trustPolicies` entry + `keys` with `provider`, `name`, `version`, `filePath`, and `scopes` will be supported. The behavior will match an equivalent `enforcement` of `any`. Future, work will add support for remainig configs.

The `provider` field, where the name of the `KeyManagementProvider` (KMP) can be specified, is assumed to be referencing a `KMP` in the ratify installatio namespace (currently the Verifier is a cluster scoped resource). If the user would like to specify a `provider` in the cluster scope, the user must append `cluster/` to the front of the `KMP` name. If the user would like to specify a a `KMP` in a different namespace, the user must append the namespace to the front of the name reference using a `/` delimiter. For example, a KMP, `test-kmp` in the `test` namespace would be referenced `test/test-kmp`.
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
          - provider: inline/inline-key-1
          - provider: inline/inline-key-2
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
          - provider: inline/inline-key
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
          - provider: inline/inline-key-build
          - provider: inline/inline-key-test
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

### How does `scopes` matching work?

`scopes` are associated per `trustPolicy`. They function to apply on top of a validation image reference and match a SINGLE trust policy to use for verification. Ratify needs to decide how to implement scope matching based on the scenarios to support. Scopes could support regular expressions however they are not as user friendly. Ratify could also define its own domain/repository pattern syntax. Or, Ratify could support both side-by-side; however, this would require having behavior to rectify if both are used at once or used for different policies. The other concern is if multiple trust policies are defined each with scopes that can apply. For example, let's take Trust Policy A which has scope `*` (any image reference works). Then, let's define Trust Policy B with scope `ghcr.io`. Finally, define Trust Policy C with scope `ghcr.io/ratify-project/ratify`. If our image to validate has reference: `ghcr.io/ratify-project/ratify:v1.2.0`, which Trust Policy should apply? Ideally, we should match to he policy that is most specific first, so Trust Policy C would be selected.

#### Scenarios to Support
1. Wildcard: `*`
2. Registry wide scope: `ghcr.io`
3. Wildcard registry domain scope: `*.azurecr.io`
4. Intermediate repository paths (repository path may reference a subpath but not an absolute path): `ghcr.io/ratify-project/*`

#### How does notation do this?

Notation's Trust Policy supports a generic `*` wildcard OR a an absolute repository path `ghcr.io/absolute/path`. There is no support for registry or wildcard registry domains. Furthermore, since only absolute repository paths are supported, there is no concern of a trust policy whose scope is a super set of another more tightly scoped trust policy.

#### Regex based matching
- Every element in `scopes` is a string regular expression. How do we figure out which policy has the tighest scope if multiple trust policies have regex that match the entire image reference?
- Regex is the most flexible and can satisfy all other requirements. However, it does require user has general understanding of regex and how to format expressions.

#### Custom pattern syntax
- Use pure sub string matching: give a string scope `s` and image reference `r`, a trust policy matches if all of `s` is a substring of `r`. This would support scope from domain all the way to tags. It could also work for partial path patterns like image reference whose path contains `/somepath/`. The tightest scope would be the longest string scope that still has a full matching substring. The trust policy selected would be the policy with a matching scope that is character-wise the longest.
- Sub-string matching does not allow for specifying positional matching behavior like "regex" does. Let's say our goal is to match image references which end with repository `/test`. In pure sub string matching if there's an intermediate repo named `test`, it will consider that a match which is NOT correct. 

#### Potential Solution
Introduce a hybrid solution that is based on substring matching:
- "tighest scope" is defined as a scope string that is longest AND has a matching substring in the image reference.
- `*` is a wildcard reserved for a trust policy that matches everything. It will have the loosest scope and will only be used iff there is NOT a tighter scope found.
- Partial path patterns like `/somepath/` are NOT supported or recommended
- wild card registry domain scope can be achieved by specifying the domain string as a scope string (example: use only ACRs --> `.azurecr.io`)
- Regex is NOT supported
- String scope will be used as an exact substring matching pattern. If there are multiple policies whose scopes match, then the policy with the longer submatch string will win.

- Problems:
  - Scope A: '.azurecr.io' and Scope B: 'test/happy/test2'. Which scope is "tighter"? Scope A scopes to a particular registry domain but Scope B works for any registry domain

#### 3/27/24 CC discussion
- Overlapping scopes is a security risk since users can inadvertently create overlapping scopes with wildcards when adding a new trust policy
- We need to enforce non overlapping scopes on verifier creation and fail if there is
- We will support:
  - `*` global scope will have least precedence and will not be considered an overlapping scope
  - multiple policies cannot define a `*` global scope. This must be validated
  - support all the way down to image level. 
  - wildcard `*` character will denote if there is a set of 0+ characters in that section of the pattern. Wildcard characters can only be used after the pattern defined. You can only specify 1 wild card character per scope.
    - example: `ghcr.io/namspace/*` will consider a scope match if there is any image reference which starts with this pattern.
  - Why can't we support multiple wild card characters? Short answer is that scope conflicts are guaranteed.
    - wildcard character before and after a pattern can lead to unintendend conflicts. Say we have 2 scopes in 2 different policies, `*/namespace/*` and `*/reponame/*`. Let's take our image reference: ghcr.io/namespace/reponame:v1. Here, both policies could match. This is NOT allowed.
  - Why can't we support wild card characters before or after the scope?
    - Scopes that support wildcards before or after CANNOT be mixed. There's always a possibility for overlap between `ghcr.io/namespace/*` & `*/reponame:v1`.
  - The main restriction is that determining scope conflicts is happening on verifier create at which point we need an ABSOLUTE way to determine if scopes are overlapping, since the image ref is not known
  - How do we support registries with unique domains (ACR, ECR, Jfrog)? You want to allows for refs with `*.azurecr.io` which is technically same as `*.azurecr.io*`.

### Implementation Details

#### Handling multiple verifications at once
- Ratify will largely mirror how cosign performs multi-signature verification
  - cannot invoke cosign's multi signature verification API since the API exposed also includes the registry content fetch which is independent in Ratify
- separate go routines per signature and collect all results PER KEY 

## Support RSA and ED25519 keys for verification

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

## Dev Work Items (WIP)
- Introduce new `KeyManagementProvider` CRD to replace `CertificateStore` (~ 2 weeks)
  - maintain old `CertificateStore` controllers and source code for backwards compat
  - define new `KeyManagementProvider` CRD + controllers
  - port certificate providers implementation to new `KMP` object
  - refactor to factory paradigm
  - refactor to define rigid config schema (currently, only a generic map of attributes passed)
  - add enforcement so only `KeyManagementProvider` OR `CertificateStore` can be enabled at a time
  - add id support for certificates in the global `Certificates` map
- Add Plugin support to `KeyManagementProvider` (~ 1 week)
- Add deprecation headers and warnings to `CertificateStore` CRD and code files (~ 0.5 weeks)
- Add Key support to `KeyManagementProvider` (~ 2-3 weeks)
  - update API
  - update Inline provider with `type` field
  - update AKV provider for `key` fetching logic
  - update controllers to add new key maps for global + namespaced keys
  - update controllers to add new certs maps for namespaced certs
- ~~Update key/certificate store logic to provide cert + key access to external plugins (see [above](#implementation-details))~~
  - ~~Option 1 or 2 depending on what's decided~~
  - ~~NOTE: If we make cosign a built-in verifier, we will NOT have to do this.~~
- Cosign Verifier: migrate to a built in verifier (~ 1-2 weeks)
- Cosign verifier multi key support (~ 3 weeks)
  - add `trustPolicies`
    - support multiple `keys` each with `provider`, and optional `name`, `version`
  - add multi key verification logic including concurrent signature verification using routines
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
- Add `KeyManagementProvider` support to CLI (~ 2 weeks)
  - Update  `verify` command group to create `KeyManagementProvider` from config
  - Update AKV provider for non Workload Identity auth

## Future Considerations
- Support `scopes` for repo based `trustPolicies` (this includes wildcard regex support)
- Support `enforcement` with `skip`, `any`, and `all`
- Support attestations with cosign signature embedded
- Support certificate based verification of cosign signatures
- Verify image annotations
- Custom signature repository
- Transparency log and SCT verification options
- Keyless signature verification options
  - Custom Rekor server
  - Github workflows