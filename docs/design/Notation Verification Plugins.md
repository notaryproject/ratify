# Notation Verification Plugins in Ratify v2

## Intro

A Notary Project signature can name a [verification plugin](https://github.com/notaryproject/specifications/blob/v1.0.0/specs/plugin-extensibility.md) in the critical attribute `io.cncf.notary.verificationPlugin`. A verifier that does not have that plugin must fail the signature. Signatures made with [AWS Signer](https://docs.aws.amazon.com/signer/latest/developerguide/image-signing-prerequisites.html) are the common case: they name `com.amazonaws.signer.notation.plugin`, which checks the signing profile and asks AWS Signer whether the signature was revoked.

Ratify v1 runs such plugins through its dynamic plugin feature. Ratify v2 creates the Notation verifier without a plugin manager, so every one of these signatures fails with:

```
plugin unsupported due to nil verifier.pluginManager
```

This document proposes the smallest change that lets Ratify v2 verify them, and lists what it leaves open.

## Goals

- Verify signatures that need a Notation verification plugin, with AWS Signer as the first user.
- No change for users who do not configure it.

Non-goals:

- Downloading or installing plugins at run time. v2 removed that on purpose.
- Shipping any plugin in the default image.

## Proposed Changes

The Notation verifier gets one optional parameter:

```yaml
verifiers:
  - name: notation-1
    type: notation
    parameters:
      trustedIdentities:
        - arn:aws:signer:us-east-1:123456789012:/signing-profiles/my_profile
      pluginDirectory: /plugins
      pluginConfig:
        aws-region: us-east-1
      certificates:
        - type: signingAuthority
          inline:
            certs: |
              <AWS Signer root certificate>
```

`pluginDirectory` uses the layout of `notation plugin install`:

```
/plugins/com.amazonaws.signer.notation.plugin/notation-com.amazonaws.signer.notation.plugin
```

When it is set, Ratify checks that the directory exists and passes `plugin.NewCLIManager(dir.NewSysFS(pluginDirectory))` as `PluginManager` to `ratify-verifier-go/notation`, which already accepts one. When it is not set, nothing changes.

The Helm chart gets the matching value `notation.pluginDirectory`. The chart does not install plugins. The plugin has to be in the image, for example:

```dockerfile
FROM ghcr.io/notaryproject/ratify-gatekeeper-provider:<version>
COPY --chown=65532:65532 notation-com.amazonaws.signer.notation.plugin \
     /plugins/com.amazonaws.signer.notation.plugin/notation-com.amazonaws.signer.notation.plugin
```

## Feature Flag

None. The parameter is optional and off by default.

## Impacted Code Paths

- `internal/verifier/notation/register.go`: new parameter, plugin manager creation.
- `deployments/ratify-gatekeeper-provider`: `notation.pluginDirectory` in `values.yaml`, `templates/executor.yaml` and the README.

The ConfigMap used with `provider.disableCRDManager` is not changed.

## Test Coverage

- Unit tests sign an artifact with a critical `io.cncf.notary.verificationPlugin` attribute and verify it through the registered verifier with a small plugin written as a shell script. Cases: plugin installed and identity trusted, identity not trusted, no plugin directory, plugin not installed, another plugin required.
- Unit tests for a missing directory and for a path that is a file.
- A bats test for the chart rendering.

Not covered: a signature made by AWS Signer. That needs an AWS account in CI.

## Backward Compatibility

No behavior change unless `pluginDirectory` is set.

## Performance

A signature that names a plugin costs two short-lived processes per verification (`get-plugin-metadata` and `verify-signature`), plus whatever the plugin does. The AWS Signer plugin calls `signer:GetRevocationStatus`. Signatures that do not name a plugin are not affected.

## Security

- The plugin runs as a child process with the environment of Ratify, including cloud credentials such as the web identity token of the pod. It must be trusted as much as Ratify itself.
- Only executables in the configured directory can run. Ratify does not download anything, and the default deployment has a read-only root file system.
- A signature that names a plugin that is not installed fails verification.

This is the trade-off the [v2 architecture proposal](./Ratify%20v2%20Architecture%20Proposal.md) wanted to leave behind for Ratify's own plugins. Notation plugins are different: the plugin contract is an executable, and the signer decides that one is required.

## Open Questions

1. How should the plugin reach the pod? Options: a user-built image (above), a build argument in the Ratify `Dockerfile`, or chart values for an extra volume and init container.
2. Plugin configuration. `notation-go` accepts `PluginConfig` per verification, and the AWS Signer plugin reads `aws-region` from it, which is needed when Ratify runs in another region than the signing profile. Ratify exposes this as the optional `pluginConfig` parameter; it requires `ratify-verifier-go` to forward it into `notation.VerifierVerifyOptions`.
3. The chart renders every Notation certificate as type `ca`. AWS Signer needs `signingAuthority`, which is in review separately.
4. Should the ConfigMap path get the same parameter?
