# nVersionCount support for Key Management Provider

Author: Josh Duffney (@duffney)

Tracked issues in scope:

- https://github.com/notaryproject/ratify/issues/1751

Proposal ref:

- https://github.com/notaryproject/ratify/blob/dev/docs/proposals/Automated-Certificate-and-Key-Updates.md

## Problem Statement

In version 1.3.0 and earlier, Ratify does not support the nVersionCount parameter for Key Management Provider (KMP) resources. This means that when a certificate or key is rotated, Ratify updates the cache with the new version and removes the previous one, which may not suit all use cases.

For instance, if a user needs to retain the last three versions of a certificate or key in the cache, Ratify cannot meet this requirement without manually adjusting the KMP resource for each new version.

By supporting nVersionCount, Ratify would allow users to specify how many versions of a certificate or key should be kept in the cache, eliminating the need for manual updates to the KMP resource.

## Proposed Solution

To address this challenge, this proposal suggests adding support for the `versionHistory` parameter to the KMP resource in Ratify. This parameter will allow users to specify the number of versions of a certificate or key that should be retained in the cache.

When a new version of a certificate or key is created, Ratify will check the `versionHistory` parameter to determine how many versions should be retained in the cache. If the number of versions exceeds the specified count, Ratify will remove the oldest version from the cache.

If a version is disabled, Ratify will remove it from the cache. This ensures that disabled versions are not retained in the cache, reducing the risk of using compromised keys or certificates being passed to the verifiers.

Example: AKV KMP resource with `versionHistory` parameter

```yaml
apiVersion: config.ratify.deislabs.io/v1beta1
kind: KeyManagementProvider
metadata:
  name: keymanagementprovider-akv
spec:
  type: azurekeyvault
  refreshInterval: 1m
  parameters:
    vaultURI: https://yourkeyvault.vault.azure.net/
    certificates:
      - name: yourCertName
        versionHistory: 2
    tenantID:
    clientID:
```

Example: AKV KMP resource status with multiple versions retained in the cache

```yaml
Status:
  Issuccess:        true
  Lastfetchedtime:  2024-10-02T14:58:54Z
  Properties:
    Certificates:
      Last Refreshed:  2024-10-02T14:58:54Z
      Name:            yourCertName
      Version:         a1b2c3d4e5f67890abcdef1234567890
      Enabled:         true
      Last Refreshed:  2024-10-02T14:58:54Z
      Name:            yourCertName
      Version:         0ff373a9259c4578a247cfd7861a8805
      Enabled:         false
```

## Implementation Details

- Modify the KMP data structure to include the status of the version.
  ```go
  type KMPMapKey struct {
  Name    string
  Version string
  Enabled string // true or false
  Created time.Time // Time the version was created used for determining the oldest version
  }
  ```
- Add the `versionHistory` parameter to the KMP resource in Ratify.
  - ensure the value cannot be less than 0 or a negative number
  - default to 2 if not specified by passing an empty value
  - maximum value should be (TBD)
  - specify the value at the object level within the parameters of the KMP resource.
- Changes to `azurekeyvault` provider:
  - support for the `versionHistory` parameter.
  - allowing retrieval of multiple versions of certificates or keys.
  - remove the oldest version from the cache when the number of versions exceeds the `versionHistory` parameter.
  - update disabled certs status in the cache & remove the certData from the cache.
- Log when the status of a version changes.
- Log when a conflict between the `versionHistory` and the number of specified certificate versions occurs.

## Dev Work Items

## Open Questions

- If a version is disabled, should it be removed from the cache or retained based on the nVersionCount and marked as inactive\disabled?
  - [x] Keep the disabled version in the cache and mark it as disabled.
- If a version is disabled, does that count towards the nVersionCount? For example, if nVersionCount is set to 3 and one of the versions is disabled, should Ratify retain the last three active versions or the last three versions, regardless of their status?
  - [x] Yes, disabled versions should count towards the nVersionCount. The reason for this is that disabled versions may be re-enabled in the future, and it is important to retain them in the cache.
- Should the existing KMP data structure be changed to group versions by key or certificate name?
  - [x] No, a flat list of versions is sufficient. At this time, there is no need to group versions by key or certificate name because the verifiers do not need to know the history of the versions.
- Should the KMP status return a flat list of versions?
  - [x] Yes, the status should return a flat list of versions.

## Future Considerations

- What should the maximum value for nVersionCount be?
  - [ ] TBD
