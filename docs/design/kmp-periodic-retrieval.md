# Periodic Key & Certificate Retrieval for KMP

Author: Josh Duffney (@duffney)

Tracked issues in scope:

- https://github.com/notaryproject/ratify/issues/1131

Proposal ref:

- https://github.com/notaryproject/ratify/blob/dev/docs/proposals/Automated-Certificate-and-Key-Updates.md

## Problem Statement

In v1.2.0 and earlier, Ratify does not support automatic refreshing, requiring manual updates to the KMP resource to accommodate key and certificate changes. This also means that Ratify continues to use the cached versions of keys or certificates, leading to potential issues such as:

**Signature Verification Failures**: When images are signed with a newly rotated key version, Ratify’s cached key version fails to verify these signatures.

**Persisting Old Images**: Signature verification may fail for older images if Ratify only caches the latest key version.

**Usage of Disabled Keys**: Disabled keys, perhaps due to compromise, may still be used by Ratify from its cache, posing security risks.

Manual updates to KMP resources to accommodate key rotation are cumbersome and prone to misconfigurations, potentially causing image verification failures and service downtime.

## Proposed Solution

To address these challenges, this proposal suggests automating the update process of KMP resources in Ratify. This can be achieved by implementing a requeue mechanism on the KMP resource at a user defined interval.

## Implementation Details

Kubernetes has a built-in feature that allows the controller's reconcile methods to be requeued, which is responsible for populating the certificate and key values from the providers in Ratify's KMP resources. This is achieved by passing {Requeue: true, RequeueAfter: interval} to the ctrl.Request returned by the KMP controller's reconcile method.

However, not all providers support being refreshed. For example, an Inline provider would not benefit from being requeued after the resource is created. To address this, the KMP interface will be updated with an isRefreshable method. This allows the provider author to indicate whether the provider supports refreshing the certificates and keys for the resource.

A new spec field called interval will be added to the keymanagementprovider_types.go file to determine when the refresh will occur. The interval can be specified as Xs, Xm, Xh, etc., indicating how often the KMP resource should refresh its certificates and keys.

Refreshing the resources involves calling the getCertificate and getKeys methods of the provider configured for each resource. If a resource is not refreshable, these methods will only be called once to set up the resource and populate the in-memory maps containing the provider's keys and certificates. If the provider is refreshable, the get methods will be called again each time the interval triggers.

An example of this implementation can be found below:

```go
// keymanagementprovider_controller.go
func (r *KeyManagementProviderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    //Do not requeue
    return ctrl.Result{}
    //Requeue
    return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 10}, nil
}
```

```go
type KeyManagementProvider interface {
	// Returns an array of certificates and the provider specific cert attributes
	GetCertificates(ctx context.Context) (map[KMPMapKey][]*x509.Certificate, KeyManagementProviderStatus, error)
	// Returns an array of keys and the provider specific key attributes
	GetKeys(ctx context.Context) (map[KMPMapKey]crypto.PublicKey, KeyManagementProviderStatus, error)
	// Returns if the provider supports refreshing of certificates & keys
	IsRefreshable() bool
}
```

```yml
## Example KMP Resource
apiVersion: config.ratify.deislabs.io/v1beta1
kind: KeyManagementProvider
metadata:
name: keymanagementprovider-akv
spec:
  type: azurekeyvault
  interval: "1m" # defines the requeue interval of the resource. Aslo supports 1s,1m,1h formats.
  parameters:
    vaultURI: https://${AKV_NAME}.vault.azure.net/
    keys:
      - name: ${KEY_NAME}
    tenantID: ${TENANT_ID}
    clientID: ${IDENTITY_CLIENT_ID}
---
apiVersion: config.ratify.deislabs.io/v1beta1
kind: KeyManagementProvider
metadata:
name: keymanagementprovider-inline
spec:
  type: inline
  parameters:
    contentType: key
    value: ${Public_Key}
```

## Dev Work Items

Suggested steps to implement the proposed solution:

- Add `isRefreshable` method to the KMP interface
- Implement a `refresh` interface that encapsulates the reconcile logic
- Add an `Interval` field to the KMP CRD spec that supports the format "Xs,Xm,Xh"

## Open Questions

- How frequently should Ratify fetch the latest key or certificate versions from the KMS?
- How should Ratify support manual updates to the KMP cache?

## Future Considerations

- Event-Driven Key & Certificate Retrieval: Implementing an event-driven mechanism to fetch the latest key or certificate versions from the KMS based on specific triggers or events.
