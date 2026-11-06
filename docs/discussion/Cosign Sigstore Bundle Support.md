# Cosign Sigstore Bundle Support in Ratify v1 and v2

Author: Xinhe Li (@fseldow)

Related PRs:

- v1: [notaryproject/ratify#3060](https://github.com/notaryproject/ratify/pull/3060) (`v1-dev`)
- v2: [notaryproject/ratify-verifier-go#83](https://github.com/notaryproject/ratify-verifier-go/pull/83), [notaryproject/ratify#3087](https://github.com/notaryproject/ratify/pull/3087) (`main`)

## Background

Cosign v3 changes the default signature format. Instead of the legacy `sha256-<digest>.sig` tag with a simple-signing payload, `cosign sign` now produces a [Sigstore bundle](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto) and attaches it to the image as an OCI 1.1 referrer:

```json
{
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
  "config": { "mediaType": "application/vnd.oci.empty.v1+json", "...": "..." },
  "layers": [
    {
      "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
      "digest": "sha256:...",
      "size": 1234
    }
  ],
  "subject": { "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:..." },
  "annotations": {
    "dev.sigstore.bundle.predicateType": "https://sigstore.dev/cosign/sign/v1",
    "dev.sigstore.bundle.content": "dsse-envelope"
  }
}
```

The layer is a protojson encoded bundle (v0.3+) containing:

- a DSSE envelope whose payload is an in-toto statement. The statement `subject` holds the image digest and the `predicateType` is `https://sigstore.dev/cosign/sign/v1` for signatures.
- verification material: a public key hint (key-based signing) or a Fulcio certificate (keyless signing).
- optional transparency log entries (Rekor v1 or Rekor v2) and RFC 3161 timestamps.

Ratify v1 and v2 only understand the legacy format today, so images signed with cosign v3 defaults fail verification.

### Signatures and attestations share the same artifact type

`cosign attest` and other Sigstore clients (e.g. GitHub artifact attestations via `actions/attest-build-provenance`) produce bundles with the **same** artifact type `application/vnd.dev.sigstore.bundle.v0.3+json`. The only difference is the in-toto predicate type, e.g. `https://slsa.dev/provenance/v1` or `https://spdx.dev/Document`. Cosign records it in the unsigned manifest annotation `dev.sigstore.bundle.predicateType` and in the signed in-toto statement.

An image commonly carries a signature from the publisher and attestations from a CI system, signed by different identities. A verifier that treats every bundle as a signature will try to verify the CI attestations with the publisher's trust policy and fail.

### How cosign verifies bundles

For reference, `cosign verify` (v3.1, new bundle format) works as follows:

1. List all referrers of the image and keep everything that parses as a Sigstore bundle. The predicate type is not checked.
2. Verify each bundle. Bundles that fail verification are ignored.
3. Succeed if at least one bundle verifies.

So cosign has "any" semantics and does not distinguish signatures from attestations: a trusted attestation alone makes `cosign verify` succeed. `cosign verify-attestation --type <predicateType>` filters by predicate type after verification.

## Goals

- Verify cosign v3 bundle signatures in v1 and v2, key-based and keyless, with Rekor v1/v2 transparency logs.
- Keep legacy cosign signature verification unchanged.
- Attestations attached to an image must not break signature verification.
- An attestation must never be accepted as a signature.

## Non-Goals

- Verifying attestations (SLSA provenance, SBOM, vulnerability reports). See [Future Work](#future-work-attestation-verification).
- Legacy cosign attestations (`.att` tag).
- Changing default policy semantics in v1 or v2.

## Design Principles

These apply to both v1 and v2.

1. **A signature is a bundle with the predicate type `https://sigstore.dev/cosign/sign/v1`.** Everything else is an attestation.
2. **Pre-filter attestations by annotation.** The verifier declines (`CanVerify` in v1, `Verifiable` in v2) bundles whose `dev.sigstore.bundle.predicateType` annotation is present and is not the signature predicate type. Declined referrers produce **no verifier report**, so they cannot fail the policy. This only needs the referrer descriptor and costs no blob fetch.
3. **Enforce the signed predicate type.** The annotation is not signed and can be changed by anyone with push access. After the bundle is verified, the verifier decodes the DSSE payload and requires the payload type `application/vnd.in-toto+json` and the predicate type `https://sigstore.dev/cosign/sign/v1`. A trusted attestation whose annotation was changed to the signature predicate type therefore fails.
4. **Fail closed when the annotation is missing.** Bundles without the annotation are verified as signatures, so an attestation without the annotation produces a failed report instead of being silently skipped.
5. **Skipping is not success.** Declining a referrer must never be reported as a successful verification. If an image only has attestations, no signature report exists and the policy fails as for an unsigned image.
6. **Only DSSE bundles are signatures.** Bundles with a message signature (`cosign sign-blob`) are rejected.
7. **The subject digest is checked with the subject's algorithm.** The verifier uses sigstore-go `verify.WithArtifactDigest(algorithm, digest)` against the in-toto subject, so SHA-512 addressed manifests are supported. Cosign's `IntotoSubjectClaimVerifier` is not used since it only reads `sha256`.

### Tampering analysis

| Attack | Result |
| --- | --- |
| Change a signature's annotation to an attestation predicate type | The signature is skipped, which is the same as deleting it. No gain. |
| Change a trusted attestation's annotation to `sign/v1` | Verified, then rejected by the signed predicate type check. |
| Remove the annotation from an attestation | Verified as a signature and rejected by the signed predicate type check (failed report). |
| Attach an attestation signed by an untrusted identity | Skipped. Does not affect the result. |

## Ratify v1

### Configuration

Bundle support is enabled by adding the bundle artifact type to `artifactTypes` of a cosign verifier with `trustPolicies`:

```yaml
apiVersion: config.ratify.deislabs.io/v1beta1
kind: Verifier
metadata:
  name: verifier-cosign
spec:
  name: cosign
  artifactTypes: application/vnd.dev.cosign.artifact.sig.v1+json,application/vnd.dev.sigstore.bundle.v0.3+json
  parameters:
    trustPolicies:
      - name: default
        scopes:
          - "*"
        keys:
          - provider: ratify-cosign-inline-key
        tLogVerify: true
```

- Only `application/vnd.dev.cosign.artifact.sig.v1+json`: legacy signatures only (current behavior).
- Only `application/vnd.dev.sigstore.bundle.v0.3+json`: bundles only.
- Both: legacy and bundle signatures.

The legacy cosign configuration (`key` / `rekorURL`) does not support bundles and returns an error asking to configure `trustPolicies`.

The Helm chart is not changed in this iteration. Users opt in through the Verifier CR. Chart support (e.g. a `cosign.signatureFormat` value) can be added separately.

### Store

The ORAS store discovers bundles through the OCI referrers API (or the referrers tag schema fallback). Referrer annotations are preserved in `ReferenceDescriptor`, so `CanVerify` can read `dev.sigstore.bundle.predicateType`. `cosignEnabled` is still needed for legacy `.sig` signatures only.

### Verification

`pkg/verifier/cosign`:

- `CanVerify` declines attestation bundles (principle 2), including when `artifactTypes` is `*`.
- `verifyInternal` detects bundle layers by media type prefix `application/vnd.dev.sigstore.bundle` and calls `verifyBundle`. Legacy layers follow the existing path.
- `verifyBundle` parses the bundle (v0.3+) and builds sigstore-go verification options from the trust policy:
  - **Key-based:** each key of the trust policy is tried. Inline/file keys use `signature.LoadDefaultVerifier`, which matches cosign v3 signing (ECDSA P-256: SHA-256, P-384: SHA-384, P-521: SHA-512). Azure Key Vault keys keep the existing hash selection based on key size/curve. With `tLogVerify: false`, an empty trusted material is used.
  - **Keyless:** the Sigstore public good trusted root is fetched via TUF and cached. Certificate identity and OIDC issuer from the trust policy are enforced. For bundles that only carry Rekor v2 entries (no integrated time), signed timestamps are required to validate the certificate.
  - `cosign.VerifyNewBundle` with `verify.WithArtifactDigest` performs signature, certificate, transparency log and subject verification.
  - The signed predicate type is enforced (principle 3).
- The report extension lists each bundle by blob digest with per-key verification results, consistent with legacy signatures.

### Policy

Each bundle referrer produces its own report, as for any other artifact in v1.

- **Config policy:** `artifactVerificationPolicies` decides per artifact type whether `all` (default) or `any` report must pass. Since attestations no longer produce reports, `all` only matters when an image carries multiple cosign **signatures** from different signers, which is a user policy choice (e.g. `"application/vnd.dev.sigstore.bundle.v0.3+json": "any"`).
- **Rego policy:** to accept an image when any cosign signature in either format passes, use `config/samples/clustered/policy/config_v1beta1_policy_rego_cosign_any.yaml`.

The default stays `all` (fail closed).

## Ratify v2

### Layering

- `ratify-verifier-go/cosign` implements the verification logic and is reused by other projects.
- `ratify/internal/verifier/cosign` wraps it with scope based routing (`register.go`).
- `ratify-go` provides the executor, the registry store and the threshold policy enforcer.

### ratify-verifier-go

New exported API:

```go
const (
    ArtifactTypeCosignSignature      = "application/vnd.dev.cosign.artifact.sig.v1+json"
    ArtifactTypeSigstoreBundle       = "application/vnd.dev.sigstore.bundle.v0.3+json"
    AnnotationKeyBundlePredicateType = "dev.sigstore.bundle.predicateType"
    PredicateTypeCosignSign          = "https://sigstore.dev/cosign/sign/v1"
)

// IsVerifiable reports whether the referrer is a legacy cosign signature or a
// Sigstore bundle signature. Attestation bundles are not verifiable.
func IsVerifiable(artifact ocispec.Descriptor) bool
```

`Verifier.Verify` dispatches on the referrer artifact type:

- Legacy signatures keep the existing path.
- Bundles: fetch the manifest and the bundle layer, parse the bundle, require a DSSE envelope, verify with sigstore-go using `verify.WithArtifactDigest` and the configured identity policies, then enforce the signed predicate type.
- Key-based verification builds one verifier per configured key. The hash follows the key type as in v1. A configured `SignatureAlgorithm` that differs from the default is accepted as well, because the v2 AKV key provider defaults to SHA-256. Nil and typed-nil keys are rejected instead of panicking.

### ratify

- Bump `ratify-verifier-go/cosign`.
- `Verifier.Verifiable` delegates to `cosign.IsVerifiable`.
- No CRD change. Verifier `parameters` are unchanged and the bundle artifact type is handled implicitly by the cosign verifier.

### Store

`ratify-go`'s registry store lists referrers with ORAS (`repo.Referrers`, with tag schema fallback) and copies manifest annotations into the descriptor passed to `Verifiable`. `allowCosignTag` is only needed for legacy `.sig` signatures.

### Policy

The threshold policy evaluates rules by `verifierName`. A rule with a verifier is satisfied when **any** artifact verified by that verifier is allowed (see `evaluationNode.calculateDecision` in `ratify-go`), and nested rules are combined with `threshold` (all by default). Therefore:

- Attestations from other signers are skipped and do not matter.
- Multiple cosign signatures where only one is trusted already pass, matching `cosign verify`.
- Requiring both a Notation and a cosign signature, or either one, is expressed with nested rules and `threshold`.

## Behavior Summary

| Scenario | `cosign verify` | Ratify v1 (config policy, default `all`) | Ratify v2 (threshold policy) |
| --- | --- | --- | --- |
| Trusted bundle signature | Pass | Pass | Pass |
| Trusted signature + untrusted attestation | Pass | Pass (attestation skipped) | Pass (attestation skipped) |
| Trusted attestation only, no signature | **Pass** | Fail | Fail |
| Attestation with annotation changed to `sign/v1` | Pass | Fail | Fail |
| Trusted signature + untrusted signature | Pass | Fail, `any` via config/rego policy | Pass |
| Legacy signature only, verifier configured for both formats | Pass (legacy path) | Pass | Pass |
| Unsigned | Fail | Fail | Fail |

## Testing

- Unit tests generate keys and DSSE bundles at test time: ECDSA P-256/P-384/P-521, wrong key, subject digest mismatch, SHA-512 subject, keyless with Fulcio/Rekor v1/Rekor v2 test entities, non-DSSE bundles, attestation predicate types, annotation spoofing and nil keys.
- v1 e2e (bats): images signed with cosign v3 (`signed-bundle`), with both formats, and with a bundle signed by an untrusted key, covering the config policy and the rego any sample.
- v2 e2e with cosign v3 signed images is a follow-up.

## Future Work: Attestation Verification

Attestations are part of cosign and use the same bundle format, trust model and verification flow as signatures. They differ only by predicate type. Instead of a new verifier type, the cosign verifier can be extended with a `predicateTypes` option:

```yaml
verifiers:
  - name: cosign-signature
    type: cosign
    parameters:
      trustPolicies: [...]          # predicateTypes defaults to [https://sigstore.dev/cosign/sign/v1]
  - name: slsa-provenance
    type: cosign
    parameters:
      predicateTypes:
        - https://slsa.dev/provenance/v1
      trustPolicies:
        - scopes: ["*"]
          certificateIdentity: https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main
          certificateOIDCIssuer: https://token.actions.githubusercontent.com
policyEnforcer:
  type: threshold-policy
  parameters:
    policy:
      rules:
        - verifierName: cosign-signature
        - verifierName: slsa-provenance
```

- Each verifier instance only claims bundles whose predicate type is in its `predicateTypes`, and enforces the signed predicate type against the same list. Today's "skip attestations" behavior is the default value of this option.
- Signatures and attestations use separate verifier instances with separate trust policies, since attestations are usually signed by CI identities. Instances must claim disjoint predicate types.
- The threshold policy already expresses "signature AND trusted provenance" without changes.
- Reports should include the predicate type and signer identity, not the full predicate, which can be large (e.g. SBOMs).
- Predicate content checks (e.g. SLSA builder ID, source repository and ref, similar to `gh attestation verify`) can follow as a second phase.

This requires `Verifiable` to depend on the verifier instance configuration. `cosign.IsVerifiable` in ratify-verifier-go is a package level function today, so the API would move to a method of `cosign.Verifier`.

## Open Questions

1. Should ratify-verifier-go replace the package level `IsVerifiable` with an instance method (and add `predicateTypes` defaulting to the signature predicate type) before [ratify-verifier-go#83](https://github.com/notaryproject/ratify-verifier-go/pull/83) is merged, to avoid an API change later?
2. Should the v1 Helm chart expose bundle verification, and with which values?
3. Should legacy cosign attestations (`.att` tag) be supported if attestation verification is added?
4. Should registries without the referrers API be documented as unsupported for bundles, or is the referrers tag schema fallback sufficient?
