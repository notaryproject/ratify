# Ratify Mutation: mutual existence of tags and digest.

## Problems

Current User scenarios:
1. I want to see which version of my image is deployed but I can only see the digest in the pod image.
   1. This results in the engineer’s time being wasted on manually mapping between the image digest and the version from the image repository.
   1. All my observability dashboards rely on tags but now I need to manually know which tags belong to which digests and somehow also make my dashboards map between those. This is a big hassle.

## Solution Overview

The current solution has been chosen on the basis that Ratify is only meant to mutate from tags to digest as tags are mutable and digests are the ultimate source of truth. This solution is also prepared with the community recommendation of using digests instead of tags in mind with digests being the ultimate source of truth for artifact verification. 

However with the digest-only approach having altercations with broader software engineers NOT focused towards security, embedding digests alongside pre-existing tags in the K8s object spec during mutation as a debug-friendly and engineer friendly way forward seems feasible. As the end container orchestration framework such as `containerd` and ultimately `runc` still continue to rely on only the mutated digest to create containers, engineers on the other hand can rely on the pre-existing and untouched tag in the deployed object (Deployment, Pod, StatefulSet etc)’s image spec to know their source of truth for debugging purposes. 

As discussed in the corresponding [Github issue](https://github.com/notaryproject/ratify/issues/1657),  having both tag & digest (`<image>:<tag>@<digest>`) is NOT a recommended option but retains status for backward compatibility, new options with default configuration adhering to this shall be discussed in the design section.

## Solution Design and Configurations / Proposed Changes

This section discusses the various additions to the current Ratify Mutator and the corresponding Helm configuration that can help resolve this problem. We also discuss features that the mutator could incorporate to facilitate other additional problems but is a topic of further discussion and debate not within the realm and scope of the problem at hand.

The solution proposes tweaks to the following sections to fix the problem at hand:
1. The helm chart shall be changed to add the corresponding new configs facilitating these new features for mutation.
1. The new configs shall be respectively passed to `/app/ratify serve` called through the `deployment.yaml` file to then handle the additional configs.
1. These configs then trickle down to the corresponding mutation code block to handle the mutations according to those config.

### Configurations

A new config block shall be added in the helm chart’s `values.yaml` which will be used respectively. 

This feature will be available through the new `provider.mutation` config block which will make the `provider.enableMutation` option obsolete. A new boolean sub-config of `provider.mutation.enable` will be added to facilitate this existing feature.

A new sub config `mutationStyle` will be added to facilitate the type of mutation the user owuld want.
The following sub-options will be added to incorporate additional configuration during mutation.

| `mutationStyle` | Implemented / Designed in the current solution? | Summary | Incoming Spec Condition | Upstream calls for Subject Descriptor? | Default Option |
| ----------- | ----------------------------------------------- | ------- | ----------------------- | -------------------------------------- | -------------- |
| `retain-mutated-tag` | Y | Retain the pre-existing tag during mutation / Do not strip the tag away if both tag & digest pre-exists |Contains Tag, Does not contain Digest / Contains Tag, Contains Digest | Y / N | false |
| `digest-only` | Y | Mutate tag to digest, stripping the tag away | Contains Tag, Does not contain Digest / Contains Tag, Contains Digest | Y / N | true |

The options can work in conjunction to provide the required mutation output.
Here, 

`Latest` tag’s digest = `xxxx`

`v1.2.4` tag’s digest = `yyyy`


| Config | Input | Output |
| ------ | ----- | ------ |
| `mutationStyle: "digest-only"` | docker.io/nginx | docker.io/nginx@sha256:xxxx |
| | docker.io/nginx:latest | docker.io/nginx@sha256:xxxx |
| | docker.io/nginx:v1.2.4 | docker.io/nginx@sha256:yyyy |
| | docker.io/nginx:latest@sha256:xxxx | docker.io/nginx@sha256:xxxx |
| | docker.io/nginx:v1.2.4@sha256:yyyy | docker.io/nginx@sha256:yyyy |
| | docker.io/nginx@sha256:xxxx | docker.io/nginx@sha256:xxxx |
| `mutationStyle: "retain-mutated-tag"` | docker.io/nginx | docker.io/nginx:latest@sha256:xxxx |
| | docker.io/nginx:v1.2.4 | docker.io/nginx:v1.2.4@sha256:yyyy |
| | docker.io/nginx:latest@sha256:xxxx | docker.io/nginx:latest@sha256:xxxx |
| | docker.io/nginx:v1.2.4@sha256:yyyy | docker.io/nginx:v1.2.4@sha256:yyyy | 
| | docker.io/nginx@sha256:xxxx | docker.io/nginx@sha256:xxxx |

An enum style config has been proposed so it does not overcrowd the `provider.mutation` block. Both, addition of new mutation styles as well as parsing on the code side will be easier with this approach.

### Implementation

The `mutationStyle` config will be implemented to retain the tag in the resulting spec image. The default option for this config will be `digest-only` to keep supporting the existing config parameter.

Options of provider.mutation.enable and provider.mutation.retainMutatedTag shall be added into Helm.
Example:

```
provider:
  tls:
    crt: ""
...
  mutation:
    // enable: true
    mutationStyle: "digest-only" // (default), other options are "retain-mutated-tag"
  enableMutation: true // deprecated, enable and use mutation.enabled instead. If both are used, `mutation.enable` will be preferred
```

The `retain-mutated-tag` option will be available for anyone wanting to control if they want to completely remove tags (the default) or have both tags + digest in the resulting output.

## Performance Impact
The solution should have very little performance impact considering addition of code will not have any network connectivity related feature. Addition of code mostly should adhere to if-else clauses and other small regex additions.

## Security Considerations
As the change is purely beautification in nature, no security impact could be thought of.
As long as research suggests all major container orchestration frameworks (docker, podman, etc) support the `tag@digest`, however it’s not guaranteed that it’ll work with other smaller frameworks where this hasn’t yet been implemented.

## Backward Compatibility
The added config won’t be backward compatible if mutation has been disabled, i.e `enableMutation:false` in the helm chart. This means that a new `provider.mutation.enable` will need to be added in the updated helm charts.
