Verification Result Cache at Executor Level
===
Author: Binbin Li (@binbin-li)

## Background

Jimmy noticed that Gatekeeper audit could trigger tons of requests to Ratify if there are many pods deployed, which might overwhelm the upstream services like remote registries. Related issue: [201](https://github.com/notaryproject/ratify/issues/201) However, as the discussion happened offline, the audit result can be cached in api server chache. And we could also configure a new CRD to batch evaluation requests in a single ED request.

Since the discussion is not finished yet, we'll just focus on how to implement the cache instead of whether we need to have it.

## Requirements

1. Cache stores the verification result for each validated images.
2. Cache can be invalidated in time to avoid incorrect validations.
3. Cache is thread-safe.


## Potential Issues

1. Since an image tag could be changed, for the cache key, it's better to use the image digest.
2. Even though the cache is thread-safe, there could be multiple read/write/update operations to the same cache entry. Cache should have a consistent behavior on it. To make it easier, we could just have get/add/delete operations without update operation.
3. Cache invalidation.
    a. Invalidate by TTL. This is a straightforward solution. But the verification result might be changed before the expiration time. On the other hand, if the TTL is too short, the cache would lose its performance value. A related question is that if we do care about the rare inconsistency result within a TTL duration as the invalidation operation does not happen so frequently.
    b. Invalidate by triggers. Since the verfication involves a lot of resources and configurations, any change to them would make the result changed and evict the cache. On the one hand, it ensures the cached result always contain the correct value. On the other hand, there are so many components and configs that could influence the result, it requires a mechanism to capture their changes and evict the result.
4. Do we really need cache on the executor level? Probably we can add more lower-level cache like registry APIs and verifier plugin results which is easier to control the invalidation.

## Design
There could be a few options to design the cache, this proposal will just focus on 2 options as mentioned above. One is TTL-based invalidation, the other is event-triggered invalidation.

### TTL-based invalidation
As mentioned above, this solution is much easier to manipulate the cache and avoids watching updates on the components involved in the verification workflow. 

However, we have to set a reasonable TTL for the cache entry. A good way is to let users config the TTL for each pod/image. As different pods may have different requirement on the result validity.
e.g. A long running pod, say 1 month, can ignore an incorrect result in a 30-second duration.

#### Follow-up
As we have discussed in the community meeting, the TTL-based option better fits the current use case and easier for implementation. However, executor-level cache is much higher granularity. We could firstly add some caches to time-consuming steps, like signature verification computing and requests to upstream services. Once we have those lower-level caches, we could do some experiments to see if it meets the requirement or find the areas that could be improved.

### Invalidate by event triggers
In an ideal system, each component in the verification could push an event per change, and Ratify would evict the cache upon receiving the event.

However, there are no such event-system available to Ratify. And there are a lot of different components that may change, including remote registry, plugin configs, certificates, trust policy of notary verifier and ratify policy. Furthermore, there could be many kinds of changes that happen to the given image, e.g. adding a new signature to it.

Therefore, this option looks more complicated than the first one. But if do need executor level cache and strong consistency with the actual verification result, we would have to find ways to solve it.


## Conclusion

As a short conclusion, if we do not have a strong consistency requirement on the verification cache, we could just adopt TTL-based invalidation. However, if we do need accurate cache all the time, then I would investigate into the event-triggered invalidation option.

## Follow-up

Since we have decided to adpot TTL-based invalidation as the first option, there are a few stages to accomplish the executor-level cache.

In this proposal, we'll focus on the verifier and store APIs.

### Store API
There are a few of APIs provided by Store interface, but only 4 of them are concerning to the verification performance.
- ListReferrers
- GetBlobContent (cache is already supported in Oras store)
- GetReferenceManifest (cache is already supported in Oras store)
- GetSubjectDescriptor
Therefore, Ratify needs to build cache for the above APIs in external store plugin and built-in plugin(Oras has 2 remaining). But there are a few issues need to be discussed.

Firstly, the `ListReferrers` API takes in a `nextToken` parameter to work with pagination. Fortunately Oras store doesn't need to take it so it can be ignored. But there could be other store plugin taking this parameter. And the `nextToken` is changeable as the pagination changes. But if we take the assumption that signature number of each image is always small, then Ratify could just cache the first page of the referrers, and fetch the next pages without cache.

Secondly, to configure the Store API cache, Ratify would need users to configure the TTL for the cache. And Ratify should support multiple levels of TTL config, which could be executor level, registry level or even repo level(repo level is to be determined as it may result in too many configuration set-up for users).

Another point we should consider is what's the default behavior if users don't set up the cache expiration time. There could be 2 options in general:
1. Disable the Cache for the unset level.
2. Enable the Cache for the unset level with a default TTL value.
    a. Since there is a default TTL value, we would need to do some experiments to get a reasonable value.


### Verifier API
Compared with Store plugin, Verifier plugin only needs to cache a single API(Verify) result. However, verifiers might invoke Store APIs to get required data. So we can regard the `verify` result as aggregation of store API responses and signature computation.

Store API cache would benefit Verifier operation. At the same Verifier cache could avoid invokation to Store APIs.

The granularity of `Verify` cache is between executor level and bottom request level. And since the most expensive remote requests are cached on Store side, there is doubt whether we need the verify cache. We could test the performance improvement once we have both store and verifier cache ready.

### Stage 1
Implement the Store API cache. Actually this stage could be divided into 2 steps. The first step is for Oras store specifically. The second step is for general store plugin though the code change would be very similar.

Components that Ratify would change/add:
1. Store config. (TBD)
    a. A new field to enable cache: enableCache bool
    b. A map field that maps overall/registry/repo to a TTL value.
    c. We also need to determine the default behavior/TTL value if it's not specified.
2. A cache interface and implementation that supports adding and evicting entries automatically.
3. As proposed by Akash in this [issue](https://github.com/notaryproject/ratify/issues/507), we can possibly add a cache lock to API cache as well.
4. Test on them.

### Stage 2
Implement the Verifier API cache. This stage could be skipped if there is no performance improvement once we test it compared with Store API cache only.

The components that Ratify needs to change/add are same to Store cache:
1. Verifier config.
2. A cache interface and implementation.
3. Test on them.

### Stage 3
The last stage is mainly for the executor level cache. At this level, cache would save a lot of invocation to both Store and Verifier APIs. But it will lose the bottom-level granularity of TTL control. We would need to see if this stage is necessary after stage 1 is done.