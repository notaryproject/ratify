# Ratify Tag to Digest Mutation
Author: Akash Singhal (@akashsinghal)

Currently, Ratify allows subject image references to be specified via tag or digest. Tags are mutable and thus not guaranteed to be referencing the same/correct image every time. Ratify should:
- Require all subject references to be specified via digest
- Implement a new tag-to-digest mutation endpoint for the ratify `httpserver` which will return the full digest reference string of a tag-specified reference input. This endpoint can be leveraged by a new External mutating data provider defined for Ratify which will be invoked by Gatekeeper's mutation webhook. 


## Add Mutation endpoint

Add a new endpoint `/ratify/gatekeeper/v1/mutate`. We will also add the accompanying handler which will utilize the referrer store to fetch the subject descriptor which will have the digest in it.

The ORAS auth provider already handles all registry authentication exchanges. As a result, no special authentication logic will need to be handled for this endpoint. However, the first authentication exchange, which is the longest, will now happen during the mutation since mutation occurs before admission. It is possible that the request could time out since the default mutation webhook timeout is 1 second (not 3 seconds).

### Add new Kubernetes templates
There doesn't seem to be GK funcitonality to have a single Provider CRD with multiple endpoints. Therefore, we must define a new provider. We will also rename the current provider to `ratify-admission-provider`

```
apiVersion: externaldata.gatekeeper.sh/v1alpha1
kind: Provider
metadata:
  name: ratify-mutation-provider
spec:
  url: {{ if .Values.provider.auth }}https{{ else }}http{{ end }}://{{ include "ratify.fullname" .}}.{{ .Release.Namespace }}:6001/ratify/gatekeeper/v1/mutation
  timeout: 7
  {{- if .Values.provider.tls.skipVerify }} # allow gatekeeper with version < 3.9.x
  insecureTLSSkipVerify: true # enable this if the provider uses HTTP so that Gatekeeper can skip TLS verification.
  {{- end }}
  {{- if .Values.provider.auth }}
  caBundle: {{ required "You must provide .Values.provider.tls.cabundle when .Values.provider.auth is set" .Values.provider.tls.cabundle }}
  {{- end }}
```

We also must define the Assign resource definition which GK uses to perform the mutation on the correct resource.

```
apiVersion: mutations.gatekeeper.sh/v1beta1
kind: Assign
metadata:
  name: mutate-subject-reference
spec:
  match:
    scope: Namespaced
    kinds:
    - apiGroups: ["apps"]
      kinds: ["Deployment", "Pod"]
    excludedNamespaces: ["gatekeeper-system"]
  applyTo:
  - groups: ["apps"]
    kinds: ["Deployment", "Pod"]
    versions: ["v1"]
  location: "spec.template.spec.containers[name:*].image"
  parameters:
    assign:
      externalData:
        provider: ratify-mutation-provider
```

## Support only digest

We have to add reference checking logic at CLI and server level so error is thrown at propogated early on.

We also need to remove the first call to registry to resolve the subject descriptor. This will require slightly altering the code to create the descriptor instead of using the one returned by registry. 

## Questions
1. Can there be multiple references provided in a single mutation request from GK?
2. Will the 1 second timeout pose an issue?
