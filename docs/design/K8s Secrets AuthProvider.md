# K8s Secrets AuthProvider
Author: Akash Singhal (@akashsinghal)

Goal: Create a Kubernetes Secret Authentication Provider which will use K8s secrets to resolve registry credentials for an artifact. In the `auth-provider` section of the ORAS plugin configuration, the `k8s-secrets` auth-provider contains a list of `secrets` where each specifies the K8s secret name along with optional `namespace` where the secret resides (the namespace ratify is deployed in will be used as the default value). Along with named secrets being used from the config, the service account linked to the Ratify pod will be queried for associated imagePullSecrets and considered during credential resolution. 

The provider will support 2 types of k8s secrets: kubernetes.io/dockercfg, kubernetes.io/dockerconfigjson

- Legacy .dockercfg Secret: kubernetes.io/dockercfg
    - Secret contains the serialized .dockercfg file
    - Extract the AuthConfigs from the serializied data (slighly different legacy format)
    - Return the corresponding registry credentials if exists
- Docker config.json Secret: kubernetes.io/dockerconfigjson
    - Secret contains the serialized config.json file
    - Extract the AuthConfigs from serialized data
    - Return the corresponding registry credentials if exists

If the user has docker config json secrets that they volume mount, then the default `docker-config` auth provider can be used instead.


NOTE: The user/service account linked to the Ratify pod must have a role binding for a get secrets Role in order for Ratify to access secrets. If secrets are across multiple namespaces, there must be role bindings for each namespace specified. Also, the ratify pod service account must have read access to the namespace service accounts in order to get the imagePullSecrets associated with the service account. 

```
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secret-reader
rules:
- apiGroups: [""] # "" indicates the core API group
  resources: ["secrets", "serviceaccounts"]
  verbs: ["get"]

---

apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-secrets
  namespace: default
subjects:
# You can specify more than one "subject"
- kind: ServiceAccount
  name: <Service Account name> # "name" is case sensitive
  namespace: default
roleRef:
  # "roleRef" specifies the binding to a Role / ClusterRole
  kind: ClusterRole #this must be Role or ClusterRole
  name: secret-reader # this must match the name of the Role or ClusterRole you wish to bind to
  apiGroup: rbac.authorization.k8s.io
```


## Sample Ratify Config File
```
{
    "stores": {
        "version": "1.0.0",
        "plugins": [
            {
                "name": "oras",
                "localCachePath": "./local_oras_cache",
                "auth-provider": {
                    "name": "k8s-secrets",
                    "serviceAccountName": "ratify-sa", // will be 'default' if not specified
                    "secrets" : [
                        {
                            "secretName": "test.ghcr.io" // ratify namespace used by default
                        },
                        {
                            "secretName": "test2.ghcr.io",
                            "namespace": "test"
                        }
                    ],
                    "secretTimeout": 43200 // in seconds - 43200s or 12h used by default if not specified
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

## Implementation Pseudocode

```
type k8SecretProviderFactory struct{}
type k8SecretAuthProvider struct {
	secrets map[string]loadedSecret
}

type secretConfig struct {
	SecretName   string `json:"secretName"`
	Namespace    string `json:"namespace,omitempty"`
}

type k8SecretAuthProviderConf struct {
	Name               string         `json:"name"`
	ServiceAccountName string         `json:"serviceAccountName,omitempty"`
	Secrets            []secretConfig `json:"secrets,omitempty"`
    SecretTimeout      uint32         `json:"secretTimeout,omitempty"`
}

func init() // init calls Register for our k8s-secrets provider

// Create returns a k8AuthProvider instance after parsing auth config and resolving
// named K8s secrets
func (s *k8SecretProviderFactory) Create(authProviderConfig AuthProviderConfig) (AuthProvider, error) {
    // unmarshal the json config for auth provider
    
    // initialize a cluster client set to access REST API
    
    // iterate through configuration secrets,resolve each secret, and store in list
        // verify each secret type is dockercfg or docker config.json

    // get service account by config name
    // get secrets listed in attached imagePullSecret in SA
    
    // return auth provider with secrets list as parameter
}

// Enabled checks if secrets list is not nil or empty
func (d *k8SecretAuthProvider) Enabled() bool

// Provide finds the secret corresponding to artifact's registryhost,
// extracts the authentication credentials from K8s secret, and
// returns AuthConfig
func (d *k8SecretAuthProvider) Provide(artifact string) (AuthConfig, error) {
    // check provider is properly Enabled
    
    // get the registry host name from the artifact string
    
    // iterate through each secret in secret list
        // if .dockercfg secret, deserialize .dockercfg data, see if matching registry host credential exists, extract auth configs and return matching AuthConfig if it exists
        // if config.json secret do same as above except using non legacy format

    // set the cache TTL to the "SecretTimeout" property (defaults to 12h)
}

```


## Questions
1. Should we support credentials at the repo level?
    - This would require us to modify how the AuthProvider interface's Provide method functions. This would also require other credential cache changes to be scoped at the repo level instead. 
2. How does AKS/EKS use imagePullSecrets?s