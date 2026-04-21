# Negative test cases for Ratify

Author: Feynman Zhou (@FeynmanZhou)

## Overview

The purpose of [negative testing](https://en.wikipedia.org/wiki/Negative_testing#:~:text=Negative%20testing%20is%20also%20known,incorrect%20values%20or%20system%20failure.) is to ensure that Ratify can gracefully handle invalid input or unexpected user behavior. It also ensures Ratify can provide useful error logs for users when handling invalid inputs or unexpected server responses. Negative test cases can also help to improve the overall quality of Ratify.

This document summarizes necessary negative test cases for Ratify.

### Areas

1. Registry (Assignee: Susan)
2. Verifier - Notation (Assignee: Binbin )
3. Certificate store (Assignee: Juncheng)
4. Policy (Assignee: @Feynman )
5. HA (Assignee: @akashsinghal  )

### OS Arch

Linux OS

- AMD x86-64 (Major)
- ARM64

## Test cases

| No  | Category     |    Description                                                                | Results |
| ------- | ------------ |  -------------------------------------------------------------------------- | ---- |
|    TC-1 | Registry     |     Users provide an mismatched registry credential in Ratify store CRD (authProvider)   | pass|
|    TC-2 | Registry     |  Registry connection timeout              | pass|
|  TC-3   | Registry     | Interact with insecure registry without the right flag (useHTTP)     | pass |
| TC-4   | Registry     | Verify a image signature without read permission to the registry.                 | pass |
|  TC-5   | Verifier | Trust Policy is not set                                     | pass |
|  TC-6   | Verifier | `registryScope` is not set or misconfigured in Trust policy                    | pass |
|  TC-7   | Verifier | Trust policy matches incorrectly and fails due to wrong certificate        | pass |
|  TC-8   | Verifier | The image signed by an untrusted identities or `trustedIdentities` was misconfigured    | pass |
|  TC-9   | Cert Store | Certificate expired  | pass |                                                |
|  TC-10   | Cert Store | Certificate revoked                                                  | pass |
| TC-11 | Cert Store | Ratify can't access AKV | pass |
| TC-12 | Cert Store | An invalid certificate is filled out in the cert store CRD (inline) | failed |
| TC-13 | Cert Store | Certificate format/type is not supported by Ratify | pass |
| TC-14 | Policy | `policyPath` is not existed | pass  |
| TC-15 | Policy | Syntax problems or misconfiguration in the REGO policy | pass |
| TC-16 | Policy | Syntax problems or misconfiguration in the Config policy  | failed |
| TC-17 | HA | A Kubernetes node that Ratify instances are running on top of it is crashed | pass|
| TC-18 | HA | Redis Pod is crashed or in outage | pass |
| TC-19 | HA | Gatekeeper instance is crashed or disconnected | N/A|
| TC-20 | HA | Dapr sidecar is not available | pass|
| TC-21 | HA | Dapr is not configured on cluster properly | pass|

## Test results

Gather the Ratify logs for each test case.

### Registry

#### TC1

```stdout
Error from server: admission webhook "mutation.gatekeeper.sh" denied the request: failed to resolve external data placeholders: failed to retrieve external data item from provider ratify-mutation-provider: Original Error: (Original Error: (HEAD "http://registry:5000/v2/notation/manifests/signed": response status code 401: Unauthorized), Error: repository operation failure, Code: REPOSITORY_OPERATION_FAILURE, Plugin Name: oras), Error: get subject descriptor failure, Code: GET_SUBJECT_DESCRIPTOR_FAILURE, Plugin Name: oras, Component Type: referrerStore, Detail: failed to get subject descriptor for image registry:5000/notation:signed
```

#### TC2

```stdout
Error from server: admission webhook "mutation.gatekeeper.sh" denied the request: failed to resolve external data placeholders: failed to retrieve external data item from provider ratify-mutation-provider: Original Error: (Original Error: (Head "https://huishwabbit2.azurecr.io/v2/net-monitor/manifests/v1": dial tcp: lookup huishwabbit2.azurecr.io on 10.0.0.10:53: no such host), Error: repository operation failure, Code: REPOSITORY_OPERATION_FAILURE, Plugin Name: oras), Error: get subject descriptor failure, Code: GET_SUBJECT_DESCRIPTOR_FAILURE, Plugin Name: oras, Component Type: referrerStore, Detail: failed to get subject descriptor for image huishwabbit2.azurecr.io/net-monitor:v1
```

#### TC3

```stdout
Error from server: admission webhook "mutation.gatekeeper.sh" denied the request: failed to resolve external data placeholders: failed to retrieve external data item from provider ratify-mutation-provider: Original Error: (Original Error: (Head "https://registry:5000/v2/notation/manifests/signed": http: server gave HTTP response to HTTPS client), Error: repository operation failure, Code: REPOSITORY_OPERATION_FAILURE, Plugin Name: oras), Error: get subject descriptor failure, Code: GET_SUBJECT_DESCRIPTOR_FAILURE, Plugin Name: oras, Component Type: referrerStore, Detail: failed to get subject descriptor for image registry:5000/notation:signed
```

#### TC4

```stdout
Error from server: admission webhook "mutation.gatekeeper.sh" denied the request: failed to resolve external data placeholders: failed to retrieve external data item from provider ratify-mutation-provider: Original Error: (Original Error: (HEAD "https://huishwabbit1.azurecr.io/v2/net-monitor/manifests/v1": response status code 401: Unauthorized), Error: repository operation failure, Code: REPOSITORY_OPERATION_FAILURE, Plugin Name: oras), Error: get subject descriptor failure, Code: GET_SUBJECT_DESCRIPTOR_FAILURE, Plugin Name: oras, Component Type: referrerStore, Detail: failed to get subject descriptor for image huishwabbit1.azurecr.io/net-monitor:v1
```

#### TC5

1.If users applied a CR without the trustPolicy, Ratify will log an error while reconciling it:

```stdout
time=2023-09-20T12:47:29.879027432Z level=error msg=Error: plugin init failure, Code: PLUGIN_INIT_FAILURE, Plugin Name: notation, Component Type: verifierunable to create verifier from verifier crd
```

2.If the trustPolicy is not set in ConfigMap of charts, Ratify will fail deployment.

#### TC6

1.If users applied a CR without registryScope, Ratify will log an error while reconciling it:

```stdout
time=2023-09-20T13:08:43.696147959Z level=error msg=Error: plugin init failure, Code: PLUGIN_INIT_FAILURE, Plugin Name: notation, Component Type: verifierunable to create verifier from verifier crd
```

2.If the registryScope is not set in ConfigMap of charts, Ratify will fail deployment.

3.If users applied a CR with misconfigured registryScope, the verification would fail:

```stdout
"verifierReports": [
    {
      "subject": "ghcr.io/ratify-project/ratify/notary-image@sha256:8e3d01113285a0e4aa574da8eb9c0f112a1eb979d72f73399d7175ba3cdb1c1b",
      "referenceDigest": "sha256:57be2c1c3d9c23ef7c964bba05c7aa23b525732e9c9af9652654ccc3f4babb0e",
      "artifactType": "application/vnd.cncf.notary.signature",
      "verifierReports": [
        {
          "isSuccess": false,
          "message": "Original Error: (Original Error: (artifact \"ghcr.io/ratify-project/ratify/notary-image@sha256:8e3d01113285a0e4aa574da8eb9c0f112a1eb979d72f73399d7175ba3cdb1c1b\" has no applicable trust policy. Trust policy applicability for a given artifact is determined by registryScopes. To create a trust policy, see: https://notaryproject.dev/docs/quickstart/#create-a-trust-policy), Error: verify signature failure, Code: VERIFY_SIGNATURE_FAILURE, Plugin Name: verifier-notation, Component Type: verifier, Documentation: https://github.com/notaryproject/notaryproject/tree/main/specs, Detail: failed to verify signature of digest), Error: verify reference failure, Code: VERIFY_REFERENCE_FAILURE, Plugin Name: verifier-notation, Component Type: verifier",
          "name": "verifier-notation",
          "type": "notation",
          "extensions": null
        }
      ],
      "nestedReports": []
    }
  ]
}
```

#### TC7

The image verification fails.

```stdout
"verifierReports": [
    {
      "subject": "ghcr.io/ratify-project/ratify/notary-image@sha256:8e3d01113285a0e4aa574da8eb9c0f112a1eb979d72f73399d7175ba3cdb1c1b",
      "referenceDigest": "sha256:57be2c1c3d9c23ef7c964bba05c7aa23b525732e9c9af9652654ccc3f4babb0e",
      "artifactType": "application/vnd.cncf.notary.signature",
      "verifierReports": [
        {
          "isSuccess": false,
          "message": "Original Error: (Original Error: (error while loading the trust store, valid certificates must be provided, only CA certificates or self-signed signing certificates are supported), Error: verify signature failure, Code: VERIFY_SIGNATURE_FAILURE, Plugin Name: verifier-notation, Component Type: verifier, Documentation: https://github.com/notaryproject/notaryproject/tree/main/specs, Detail: failed to verify signature of digest), Error: verify reference failure, Code: VERIFY_REFERENCE_FAILURE, Plugin Name: verifier-notation, Component Type: verifier",
          "name": "verifier-notation",
          "type": "notation",
          "extensions": null
        }
      ],
      "nestedReports": []
    }
  ]
```

#### TC8

The image verification fails:

```stdout
time=2023-09-22T13:50:40.440640495Z level=info msg=verify result for subject ghcr.io/ratify-project/ratify/notary-image@sha256:8e3d01113285a0e4aa574da8eb9c0f112a1eb979d72f73399d7175ba3cdb1c1b: {
  "verifierReports": [
    {
      "isSuccess": false,
      "name": "verifier-notation",
      "type": "notation",
      "message": "Original Error: (Original Error: (error while parsing the certificate subject from the digital signature. error : \"distinguished name (DN) \\\"CN=ratify.default\\\" has no mandatory RDN attribute for \\\"C\\\", it must contain 'C', 'ST', and 'O' RDN attributes at a minimum\"), Error: verify signature failure, Code: VERIFY_SIGNATURE_FAILURE, Plugin Name: verifier-notation, Component Type: verifier, Documentation: https://github.com/notaryproject/notaryproject/tree/main/specs, Detail: failed to verify signature of digest), Error: verify reference failure, Code: VERIFY_REFERENCE_FAILURE, Plugin Name: verifier-notation, Component Type: verifier",
      "artifactType": "application/vnd.cncf.notary.signature"
    }
  ]
}
```

#### TC10

```stdout
time=2023-09-22T08:58:54.288013215Z level=error msg=Reconciler error CertificateStore=gatekeeper-system/certstore-akv controller=certificatestore controllerGroup=config.ratify.deislabs.io controllerKind=CertificateStore error=Error fetching certificates in store certstore-akv with azurekeyvault provider, error: failed to get secret objectName:wabbit-network-io, objectVersion:, error: keyvault.BaseClient#GetSecret: Failure responding to request: StatusCode=404 -- Original Error: autorest/azure: Service returned an error. Status=404 Code="SecretNotFound" Message="A secret with (name/id) wabbit-network-io was not found in this key vault. If you recently deleted this secret you may be able to recover it using the correct recovery command. For help resolving this issue, please see https://go.microsoft.com/fwlink/?linkid=2125182" name=certstore-akv namespace=gatekeeper-system reconcileID=28eac175-4f3b-4353-88df-df5bdc3ae6de
```

#### TC12

The inline cert is invalid and has an error but Ratify logs doesn't mentioned the root cause.

```stdout
time=2023-09-21T17:11:38.097617136Z level=info msg=received request POST /ratify/gatekeeper/v1/verify
time=2023-09-21T17:11:38.097677237Z level=info msg=start request POST /ratify/gatekeeper/v1/verify component-type=server go.version=go1.20.8 trace-id=8c82c679-037d-4973-9d3b-ba955c8a73a0
time=2023-09-21T17:11:38.097999243Z level=info msg=verifying subject ghcr.io/feynmanzhou/net-monitor@sha256:27c0290c485140c3c998e92c6ef23fba2bd9f09c8a1c7adb24a1d2d274ce3e8e component-type=server go.version=go1.20.8 trace-id=8c82c679-037d-4973-9d3b-ba955c8a73a0
time=2023-09-21T17:11:38.098228648Z level=info msg=Resolve of the image completed successfully the digest is sha256:27c0290c485140c3c998e92c6ef23fba2bd9f09c8a1c7adb24a1d2d274ce3e8e component-type=executor go.version=go1.20.8 trace-id=8c82c679-037d-4973-9d3b-ba955c8a73a0
time=2023-09-21T17:11:38.098545355Z level=warning msg=Error: cache not set, Code: CACHE_NOT_SET, Component Type: cache, Detail: failed to set auth cache for ghcr.io component-type=referrerStore go.version=go1.20.8 trace-id=8c82c679-037d-4973-9d3b-ba955c8a73a0
time=2023-09-21T17:11:38.625152926Z level=info msg=Resolve of the image completed successfully the digest is sha256:f4c1e923d1f2a7b76513c889a0db548a093f422d06ac6b83ce7243e0c8fa7805 component-type=executor go.version=go1.20.8 trace-id=8c82c679-037d-4973-9d3b-ba955c8a73a0
time=2023-09-21T17:11:38.625312829Z level=warning msg=Error: cache not set, Code: CACHE_NOT_SET, Component Type: cache, Detail: failed to set auth cache for ghcr.io component-type=referrerStore go.version=go1.20.8 trace-id=8c82c679-037d-4973-9d3b-ba955c8a73a0
time=2023-09-21T17:11:38.625165626Z level=warning msg=Error: cache not set, Code: CACHE_NOT_SET, Component Type: cache, Detail: failed to set auth cache for ghcr.io component-type=referrerStore go.version=go1.20.8 trace-id=8c82c679-037d-4973-9d3b-ba955c8a73a0
time=2023-09-21T17:11:38.625883641Z level=warning msg=Error: cache not set, Code: CACHE_NOT_SET, Component Type: cache, Detail: failed to set auth cache for ghcr.io component-type=referrerStore go.version=go1.20.8 trace-id=8c82c679-037d-4973-9d3b-ba955c8a73a0
time=2023-09-21T17:11:38.904404237Z level=info msg=verify result for subject ghcr.io/feynmanzhou/net-monitor@sha256:27c0290c485140c3c998e92c6ef23fba2bd9f09c8a1c7adb24a1d2d274ce3e8e: {
  "verifierReports": [
    {
      "subject": "ghcr.io/feynmanzhou/net-monitor@sha256:27c0290c485140c3c998e92c6ef23fba2bd9f09c8a1c7adb24a1d2d274ce3e8e",
      "referenceDigest": "sha256:f4c1e923d1f2a7b76513c889a0db548a093f422d06ac6b83ce7243e0c8fa7805",
      "artifactType": "application/vnd.cncf.notary.signature",
      "verifierReports": [
        {
          "isSuccess": false,
          "message": "Original Error: (Original Error: (signature is not produced by a trusted signer), Error: verify signature failure, Code: VERIFY_SIGNATURE_FAILURE, Plugin Name: verifier-notation, Component Type: verifier, Documentation: https://github.com/notaryproject/notaryproject/tree/main/specs, Detail: failed to verify signature of digest), Error: verify reference failure, Code: VERIFY_REFERENCE_FAILURE, Plugin Name: verifier-notation, Component Type: verifier",
          "name": "verifier-notation",
          "type": "notation",
          "extensions": null
        }
      ],
      "nestedReports": []
    }
  ]
} component-type=server go.version=go1.20.8 trace-id=8c82c679-037d-4973-9d3b-ba955c8a73a0
```

#### TC13

```stdout
 Error: plugin init failure, Code: PLUGIN_INIT_FAILURE, Plugin Name: azurekeyvault, Component Type: certProvider, Documentation: https://learn.microsoft.com/en-us/azure/key-vault/general/overview, Detail: failed to get keyvault client name=certstore-akv namespace=default reconcileID=a68577aa-af1f-4e87-8f3a-2296d6680934
 ```

#### TC14

```stdout
time=2023-09-21T16:49:39.101904574Z level=info msg=verify result for subject ghcr.io/feynmanzhou/net-monitor@sha256:27c0290c485140c3c998e92c6ef23fba2bd9f09c8a1c7adb24a1d2d274ce3e8e: {
  "verifierReports": [
    {
      "isSuccess": false,
      "name": "verifier-notation",
      "type": "notation",
      "message": "Original Error: (Original Error: (signature is not produced by a trusted signer), Error: verify signature failure, Code: VERIFY_SIGNATURE_FAILURE, Plugin Name: verifier-notation, Component Type: verifier, Documentation: https://github.com/notaryproject/notaryproject/tree/main/specs, Detail: failed to verify signature of digest), Error: verify reference failure, Code: VERIFY_REFERENCE_FAILURE, Plugin Name: verifier-notation, Component Type: verifier",
      "artifactType": "application/vnd.cncf.notary.signature"
    }
  ]
} component-type=server go.version=go1.20.8 trace-id=871c479e-4d1a-413b-b6b5-a4332873afc7
time=2023-09-21T16:49:39.649743359Z level=info msg=Reconciling Policy regopolicy
time=2023-09-21T16:49:39.652539916Z level=info msg=selected policy provider: regopolicy
time=2023-09-21T16:49:39.65272052Z level=info msg=Deleting policy configpolicy
time=2023-09-21T16:49:39.660718083Z level=info msg=Deleted policynameconfigpolicy
time=2023-09-21T16:49:39.660797685Z level=info msg=Reconciling Policy configpolicy
time=2023-09-21T16:49:39.660900987Z level=error msg=failed to get Policy: Policy.config.ratify.deislabs.io "configpolicy" not found
time=2023-09-21T16:49:49.266265821Z level=info msg=received request POST /ratify/gatekeeper/v1/mutate
time=2023-09-21T16:49:49.266514626Z level=info msg=start request POST /ratify/gatekeeper/v1/mutate component-type=server go.version=go1.20.8 trace-id=acb4f156-8132-4cfb-9df6-e73266c5c6c7
time=2023-09-21T16:49:49.26667593Z level=info msg=mutating image ghcr.io/ratify-project/ratify/notary-image:signed component-type=server go.version=go1.20.8 trace-id=acb4f156-8132-4cfb-9df6-e73266c5c6c7
time=2023-09-21T16:49:49.266880934Z level=warning msg=Error: cache not set, Code: CACHE_NOT_SET, Component Type: cache, Detail: failed to set auth cache for ghcr.io component-type=referrerStore go.version=go1.20.8 trace-id=acb4f156-8132-4cfb-9df6-e73266c5c6c7
```

#### TC15

```stdout
time=2023-09-21T16:24:03.422952769Z level=error msg=Reconciler error Policy=regopolicy controller=policy controllerGroup=config.ratify.deislabs.io controllerKind=Policy error=failed to create policy enforcer: failed to create policy provider: Original Error: (Original Error: (failed to create policy engine: failed to create policy query, err: failed to prepare rego query, err: 1 error occurred: policy.rego:13: rego_unsafe_var_error: var fals is unsafe), Error: plugin init failure, Code: PLUGIN_INIT_FAILURE, Plugin Name: regopolicy, Component Type: policyProvider, Documentation: https://github.com/notaryproject/ratify/blob/main/docs/reference/providers.md#policy-providers, Detail: failed to create OPA engine), Error: plugin init failure, Code: PLUGIN_INIT_FAILURE, Plugin Name: regopolicy, Component Type: policyProvider, Documentation: https://github.com/notaryproject/ratify/blob/main/docs/reference/providers.md#policy-providers, Detail: failed to create policy provider name=regopolicy namespace= reconcileID=71adeaf9-a6f0-4974-88cf-34bd2be47a99
```

#### TC16

I misconfigured the config policy but the Ratify logs don't point this root cause out.

```stdout
time=2023-09-21T16:42:38.410494337Z level=info msg=received request POST /ratify/gatekeeper/v1/verify
time=2023-09-21T16:42:38.410757342Z level=info msg=start request POST /ratify/gatekeeper/v1/verify component-type=server go.version=go1.20.8 trace-id=96f67e50-2bbe-42c6-98ac-fb0c7e41be96
time=2023-09-21T16:42:38.411028347Z level=info msg=verifying subject ghcr.io/feynmanzhou/net-monitor@sha256:27c0290c485140c3c998e92c6ef23fba2bd9f09c8a1c7adb24a1d2d274ce3e8e component-type=server go.version=go1.20.8 trace-id=96f67e50-2bbe-42c6-98ac-fb0c7e41be96
time=2023-09-21T16:42:38.411223651Z level=info msg=Resolve of the image completed successfully the digest is sha256:27c0290c485140c3c998e92c6ef23fba2bd9f09c8a1c7adb24a1d2d274ce3e8e component-type=executor go.version=go1.20.8 trace-id=96f67e50-2bbe-42c6-98ac-fb0c7e41be96
time=2023-09-21T16:42:38.411495657Z level=warning msg=Error: cache not set, Code: CACHE_NOT_SET, Component Type: cache, Detail: failed to set auth cache for ghcr.io component-type=referrerStore go.version=go1.20.8 trace-id=96f67e50-2bbe-42c6-98ac-fb0c7e41be96
time=2023-09-21T16:42:38.876979537Z level=warning msg=Error: cache not set, Code: CACHE_NOT_SET, Component Type: cache, Detail: failed to set auth cache for ghcr.io component-type=referrerStore go.version=go1.20.8 trace-id=96f67e50-2bbe-42c6-98ac-fb0c7e41be96
time=2023-09-21T16:42:38.877157441Z level=warning msg=Error: cache not set, Code: CACHE_NOT_SET, Component Type: cache, Detail: failed to set auth cache for ghcr.io component-type=referrerStore go.version=go1.20.8 trace-id=96f67e50-2bbe-42c6-98ac-fb0c7e41be96
time=2023-09-21T16:42:38.878372465Z level=info msg=verify result for subject ghcr.io/feynmanzhou/net-monitor@sha256:27c0290c485140c3c998e92c6ef23fba2bd9f09c8a1c7adb24a1d2d274ce3e8e: {
  "verifierReports": [
    {
      "isSuccess": false,
      "name": "verifier-notation",
      "type": "notation",
      "message": "Original Error: (Original Error: (signature is not produced by a trusted signer), Error: verify signature failure, Code: VERIFY_SIGNATURE_FAILURE, Plugin Name: verifier-notation, Component Type: verifier, Documentation: https://github.com/notaryproject/notaryproject/tree/main/specs, Detail: failed to verify signature of digest), Error: verify reference failure, Code: VERIFY_REFERENCE_FAILURE, Plugin Name: verifier-notation, Component Type: verifier",
      "artifactType": "application/vnd.cncf.notary.signature"
    }
  ]
} component-type=server go.version=go1.20.8 trace-id=96f67e50-2bbe-42c6-98ac-fb0c7e41be96
```

#### TC17

SSH into one of the nodes that has a ratify replica scheduled on it. Manually `reboot` the node. Immediately execute pod creation commands.

```stdout
Error from server: admission webhook "mutation.gatekeeper.sh" denied the request: failed to resolve external data placeholders: failed to send external data request to provider ratify-mutation-provider: failed to send external data request: Post "https://ratify.gatekeeper-system:6001/ratify/gatekeeper/v1/mutate": dial tcp 10.0.254.84:6001: connect: no route to host
```

There's a short period of time when the node health is not known to be degraded yet. During this service will continue to route requests to dead pods. Once node health is degraded, the requests seem to all route to healthy instance.

#### TC18

The Redis stateful sets (master + replica) were drained to 0

Error from `kubectl run` output:

```stdout
Error from server: admission webhook "mutation.gatekeeper.sh" denied the request: failed to resolve external data placeholders: failed to validate external data response from provider ratify-mutation-provider: non-empty system error: operation failed with error operation timed out after duration 1.95s
```

Ratify Logs:

```stdout
time=2023-09-21T20:49:55.965807677Z level=info msg=received request POST /ratify/gatekeeper/v1/mutate 
time=2023-09-21T20:49:55.965917879Z level=info msg=start request POST /ratify/gatekeeper/v1/mutate component-type=server go.version=go1.20.8 trace-id=084fab3d-0f0d-4f32-9a9b-03db3c3df5fa
time=2023-09-21T20:49:55.966001082Z level=info msg=mutating image ghcr.io/ratify-project/ratify/notary-image:signed component-type=server go.version=go1.20.8 trace-id=084fab3d-0f0d-4f32-9a9b-03db3c3df5fa
time=2023-09-21T20:49:57.916645653Z level=debug msg=subject descriptor cache miss for value: ghcr.io/ratify-project/ratify/notary-image:signed component-type=referrerStore go.version=go1.20.8 trace-id=084fab3d-0f0d-4f32-9a9b-03db3c3df5fa
time=2023-09-21T20:49:57.916739655Z level=debug msg=auth cache miss component-type=referrerStore go.version=go1.20.8 trace-id=084fab3d-0f0d-4f32-9a9b-03db3c3df5fa
time=2023-09-21T20:49:57.917014862Z level=error msg=Error saving value to redis: error saving state: rpc error: code = DeadlineExceeded desc = context deadline exceeded component-type=cache go.version=go1.20.8 trace-id=084fab3d-0f0d-4f32-9a9b-03db3c3df5fa
time=2023-09-21T20:49:57.917058964Z level=warning msg=Error: cache not set, Code: CACHE_NOT_SET, Component Type: cache, Detail: failed to set auth cache for ghcr.io component-type=referrerStore go.version=go1.20.8 trace-id=084fab3d-0f0d-4f32-9a9b-03db3c3df5fa
time=2023-09-21T20:49:57.917228968Z level=debug msg=mutation: execution time for request: 1951ms component-type=server go.version=go1.20.8 trace-id=084fab3d-0f0d-4f32-9a9b-03db3c3df5fa
```

Audit also begins to fail with timeout of 4.9 second.

```stdout
time=2023-09-21T20:52:45.703791311Z level=info msg=received request POST /ratify/gatekeeper/v1/verify 
time=2023-09-21T20:52:45.703840611Z level=info msg=start request POST /ratify/gatekeeper/v1/verify component-type=server go.version=go1.20.8 trace-id=384a4c5e-6654-47a8-bdaa-16823df527ac
time=2023-09-21T20:52:45.703937712Z level=info msg=verifying subject ghcr.io/ratify-project/ratify/notary-image@sha256:8e3d01113285a0e4aa574da8eb9c0f112a1eb979d72f73399d7175ba3cdb1c1b component-type=server go.version=go1.20.8 trace-id=384a4c5e-6654-47a8-bdaa-16823df527ac
time=2023-09-21T20:52:50.604600679Z level=debug msg=subject descriptor cache miss for value: ghcr.io/ratify-project/ratify/notary-image@sha256:8e3d01113285a0e4aa574da8eb9c0f112a1eb979d72f73399d7175ba3cdb1c1b component-type=referrerStore go.version=go1.20.8 trace-id=384a4c5e-6654-47a8-bdaa-16823df527ac
time=2023-09-21T20:52:50.604668279Z level=debug msg=auth cache miss component-type=referrerStore go.version=go1.20.8 trace-id=384a4c5e-6654-47a8-bdaa-16823df527ac
time=2023-09-21T20:52:50.60472728Z level=error msg=Error saving value to redis: error saving state: rpc error: code = DeadlineExceeded desc = context deadline exceeded component-type=cache go.version=go1.20.8 trace-id=384a4c5e-6654-47a8-bdaa-16823df527ac
time=2023-09-21T20:52:50.60474728Z level=warning msg=Error: cache not set, Code: CACHE_NOT_SET, Component Type: cache, Detail: failed to set auth cache for ghcr.io component-type=referrerStore go.version=go1.20.8 trace-id=384a4c5e-6654-47a8-bdaa-16823df527ac
time=2023-09-21T20:52:50.60483898Z level=warning msg=Original Error: (Original Error: (Head "https://ghcr.io/v2/ratify-project/ratify/notary-image/manifests/sha256:8e3d01113285a0e4aa574da8eb9c0f112a1eb979d72f73399d7175ba3cdb1c1b": context deadline exceeded), Error: repository operation failure, Code: REPOSITORY_OPERATION_FAILURE, Plugin Name: oras), Error: get subject descriptor failure, Code: GET_SUBJECT_DESCRIPTOR_FAILURE, Plugin Name: oras, Component Type: referrerStore, Detail: failed to resolve the subject descriptor component-type=referrerStore go.version=go1.20.8 trace-id=384a4c5e-6654-47a8-bdaa-16823df527ac
time=2023-09-21T20:52:50.60485408Z level=debug msg=cache miss for subject ghcr.io/ratify-project/ratify/notary-image@sha256:8e3d01113285a0e4aa574da8eb9c0f112a1eb979d72f73399d7175ba3cdb1c1b component-type=server go.version=go1.20.8 trace-id=384a4c5e-6654-47a8-bdaa-16823df527ac
time=2023-09-21T20:52:50.60487278Z level=error msg=Error saving value to redis: error saving state: rpc error: code = DeadlineExceeded desc = context deadline exceeded component-type=cache go.version=go1.20.8 trace-id=384a4c5e-6654-47a8-bdaa-16823df527ac
time=2023-09-21T20:52:50.60488398Z level=warning msg=unable to insert cache entry for subject ghcr.io/ratify-project/ratify/notary-image@sha256:8e3d01113285a0e4aa574da8eb9c0f112a1eb979d72f73399d7175ba3cdb1c1b component-type=server go.version=go1.20.8 trace-id=384a4c5e-6654-47a8-bdaa-16823df527ac
time=2023-09-21T20:52:50.60490018Z level=info msg=verify result for subject ghcr.io/ratify-project/ratify/notary-image@sha256:8e3d01113285a0e4aa574da8eb9c0f112a1eb979d72f73399d7175ba3cdb1c1b: {
  "verifierReports": [
    {
      "subject": "ghcr.io/ratify-project/ratify/notary-image@sha256:8e3d01113285a0e4aa574da8eb9c0f112a1eb979d72f73399d7175ba3cdb1c1b",
      "isSuccess": false,
      "message": "verification failed: Error: referrer store failure, Code: REFERRER_STORE_FAILURE, Component Type: referrerStore, Detail: could not resolve descriptor for a subject from any stores"
    }
  ]
} component-type=server go.version=go1.20.8 trace-id=384a4c5e-6654-47a8-bdaa-16823df527ac
```

The original `mutation exceeded 1.95s` error does not immediately point to what the root cause. Scanning through logs, you eventually see `context deadline exceeded` errors for cache writes which points to underlying cache being unavailable.

#### TC19

N/A

#### TC20

Scale dapr-side-car inject deployment to 0. Scale ratify deployment to 0. Scale ratify deployment back up to 2. Now the daprd sidecar containers will not be present on each pod.

Ratify pod will fail to startup if no daprd pod is enabled. This is due to cache intialization failure which is currently a blocking error.

Logs

```stdout
dapr client initializing for: 127.0.0.1:50001
Error: error initializing cache of type dapr: error creating default client: error creating connection to '127.0.0.1:50001': context deadline exceeded
```

#### TC21

Force a Dapr installation misconfiguration by not applying the redis StateStore CR.

User will not see any errors when applying pods/deployment. Perf will be degraded an may lead to more timeouts.

From logs, cache errors:

```stdout
time=2023-09-21T22:17:50.216846963Z level=error msg=Error saving value to redis: error saving state: rpc error: code = FailedPrecondition desc = state store is not configured component-type=cache go.version=go1.20.8 trace-id=99e8aed9-e944-4e6f-8588-d7be7d16f940
```

### From Xinhe

```stdout
level=error msg=Reconciler error CertificateStore=default/certstore-incorrect-cert controller=certificatestore controllerGroup=config.ratify.deislabs.io controllerKind=CertificateStore error=Error fetching certificates in store certstore-incorrect-cert with inline provider, error: Error: cert invalid, Code: CERT_INVALID, Component Type: certProvider name=certstore-incorrect-cert namespace=default reconcileID=6a444f61-fed0-4d0a-b6e1-08bedbe90712
time=2023-09-22T01:55:54.866028606Z level=warning msg=no certificate fetched for certStore certstore-incorrect-cert component-type=verifier go.version=go1.20.8 trace-id=4b6580f6-8b08-4c0b-a1ab-d4264298a6c9
time=2023-09-22T01:55:54.866327608Z level=info msg=verify result for subject ghcr.io/ratify-project/ratify/notary-image@sha256:8e3d01113285a0e4aa574da8eb9c0f112a1eb979d72f73399d7175ba3cdb1c1b: {
  "verifierReports": [
    {
      "isSuccess": false,
      "name": "verifier-notation",
      "type": "notation",
      "message": "Original Error: (Original Error: (error while loading the trust store, unable to fetch certificates for namedStore: certs), Error: verify signature failure, Code: VERIFY_SIGNATURE_FAILURE, Plugin Name: verifier-notation, Component Type: verifier, Documentation: https://github.com/notaryproject/notaryproject/tree/main/specs, Detail: failed to verify signature of digest), Error: verify reference failure, Code: VERIFY_REFERENCE_FAILURE, Plugin Name: verifier-notation, Component Type: verifier",
      "artifactType": "application/vnd.cncf.notary.signature"
    }
  ]
}
```
