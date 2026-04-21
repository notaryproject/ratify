# Add Authentication Provider Support For ORAS Store

Author: Akash Singhal (@akashsinghal)

General Design Document for [Ratify Auth](https://hackmd.io/LFWPWM7wT_icfIPZbuax0Q#Auth-using-metadata-service-endpoint-in-k8s)

Linked PR: https://github.com/notaryproject/ratify/pull/123


## Goals
1. Add AuthProvider extensible interface with AuthConfig spec mirroring Docker AuthConfig. Used only for ORAS store.
2. Modify ORAS Store to consume AuthConfig for authentication. AuthConfig provided by AuthProvider specificied in config for ORAS plugin

Each Referrer store is likely to have different authentication requirements (e.g. a SQL DB referrer store doesn't use Docker Auth and instead relies on secure connection strings). Therefore, the Authentication Provider interface will be specific to each referrer store. In this case the `AuthProvider` will be specific to ORAS. 

Currently, ORAS is undergoing a major refactor which will culminate in a v2 release that alters the way credentials are handled by a remote registry. Prior to that release, we must rely upon traditional `AuthConfig` to provide credentials to registry. Once we decide to transition to the v2 API, the ratify refactor will include switching to using the ORAS [Credential object](https://github.com/oras-project/oras-go/blob/6dfff48efc4fd0c3b13ae202d505093426137554/registry/remote/auth/credential.go#L22). Since we don't want to specifically block on a stable v2 version release for ORAS we will rely upon `AuthConfig` in the mean time. The switch over should not be that involved. 

## ORAS Store Authentication Interfaces

### Sample Ratify Config File

```
{
    "stores": {
        "version": "1.0.0",
        "plugins": [
            {
                "name": "oras",
                "localCachePath": "./local_oras_cache",
                "auth-provider": {
                    "name": "<auth provider name>",
                    <other provider specific fields>
                }
            }
        ]
    },
    "verifiers": {
        "version": "1.0.0",
        "plugins": [
            {
                "name":"notaryv2",
                "artifactTypes" : "application/vnd.cncf.notary.v2.signature",
                "verificationCerts": [
                    "<cert folder>"
                  ]
            }  
        ]
    }
}
```
### AuthProvider Interface

Based on [DockerConfigProvider](https://github.com/kubernetes/kubernetes/blob/2cd8ceb2694ef30d93cccb53445e9add6cbd9f7f/pkg/credentialprovider/provider.go#L30)

```
type AuthProvider interface {
    // Enabled returns true if the config provider is properly enabled
    // It will verify necessary values provided in config file to
    // create the AuthProvider
    Enabled() bool 
    // Provide returns AuthConfig for registry.
    Provide(artifact string) (AuthConfig, error)
}
```

### AuthConfig Object

Based on [DockerConfig](https://github.com/kubernetes/kubernetes/blob/2cd8ceb2694ef30d93cccb53445e9add6cbd9f7f/pkg/credentialprovider/config.go#L50)

```
// This config that represents the credentials that should be used
// when pulling artifacts from specific repositories.
type AuthConfig struct {
	Username string
	Password string

	Provider AuthProvider
    
    // Add more fields if necessary such as access tokens
}
```

### Files Added
- Create AuthProvider file with default docker config provider implementation like [K8s](https://github.com/kubernetes/kubernetes/blob/2cd8ceb2694ef30d93cccb53445e9add6cbd9f7f/pkg/credentialprovider/provider.go).

```
type AuthProvider interface {
    // Enabled returns true if the config provider is properly enabled
    // It will verify necessary values provided in config file to
    // create the AuthProvider
    Enabled() bool 
    // Provide returns AuthConfig for registry.
    Provide(artifact string) (AuthConfig, error)
}


type defaultProviderFactory struct{}
type defaultAuthProvider struct{}

// init calls Register for our default provider, which simply reads the .dockercfg file.
func init() {
    AuthProviderFactory.Register("default", &defaultProviderFactory)
}

// Create defaultAuthProvider
func (s *defaultProviderFactory) Create(authProviderConfig AuthProviderConfig) (AuthProvider, error)

// Enabled implements AuthProvider; Always returns true for the default provider
func (d *defaultAuthProvider) Enabled() bool

// Provide implements AuthProvider; reads docker config file and returns corresponding credentials from file if exists
func (d *defaultAuthProvider) Provide(artifact string) (AuthConfig, error) 

```
- Create AuthProviderFactory  which will register new AuthProviderFactory for a new AuthProvider and return the correct AuthProvider given the AuthProviderConfig 
```
var builtInAuthProviders = make(map[string]AuthProviderFactory)

// AuthProviderFactory is an interface that defines methods to create an AuthProvider
type AuthProviderFactory interface {
	Create(authProviderConfig AuthProviderConfig) (AuthProvider, error)
}

// Add the factory to the built in providers map
func Register(name string, factory AuthProviderFactory)

// CreateAuthProviderFromConfig creates AuthProvider from the provided configuration
// If the AuthProviderConfig isn't specified, use default auth provider
func CreateAuthProviderFromConfig(authProviderConfig AuthProviderConfig) (AuthProvider, error)

func validateAuthProviderConfig(authProviderConfig AuthProviderConfig) error

```
- AuthProviderConfig definition is simply a map to the provided AuthProviderConfig 

```
// AuthProviderConfig represents the configuration of an AuthProvider
type AuthProviderConfig map[string]interface{}
```

## ORAS Store Modification

### Changes to Accept New AuthProvider Config

Add AuthProviderConfig object in OrasConfig:
```
type OrasStoreConf struct {
	Name           string             `json:"name"`
	UseHttp        bool               `json:"useHttp,omitempty"`
	CosignEnabled  bool               `json:"cosign-enabled,omitempty"`
	AuthProvider   AuthProviderConfig `json:"auth-provider,omitempty"`
	LocalCachePath String             `json:"localCachePath,omitempty"`
}
```

Update `Create` [method](https://github.com/notaryproject/ratify/blob/6edd4ceedc21cf704857eae56b2197e0e28f0f93/pkg/referrerstore/oras/oras.go#L68) in oras.go

```
func (s *orasStoreFactory) Create(version string, storeConfig config.StorePluginConfig) (referrerstore.ReferrerStore, error) {
    ...
    
    // Call the AuthProviderFactory CreateAuthProvidersFromConfig method with the AuthProviderConfig parameter
    
    ...
}
```

### Changes to use new AuthProvider

```
func (store *orasStore) createRegistryClient(targetRef common.Reference) (*content.Registry, error) {
    ...
    
    // Use AuthProvider's Provide method to get repository's AuthConfig
    // Specify the Username and Password in the RegistryOptions
    
    ...
    
    return content.NewRegistryWithDiscover(targetRef.Original, registryOpts)
}
```
**NOTE: We need to migrate ORAS store to new ORAS-go v2 library

# Questions

1. For each store, should we support multiple auth providers or just one?
    - No. We currently can't think of a scenario where multiple AuthProviders would be needed for a single store
2. ORAS store relies upon the artifacts implementation of ORAS in v1 while the new ORAS auth is in v2. Do we stick with current version of ORAS and build AuthCredentials integration with ORAS v1?
    - We will eventually migrate to the v2 oras-go library once released. For now all implementations will work with v1

