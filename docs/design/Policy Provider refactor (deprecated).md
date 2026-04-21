# Ratify Policy Provider
Author: Akash Singhal (@akashsinghal)

Prerequisite: Read through the Executor Policy design section of this [doc](https://github.com/notaryproject/ratify/tree/main/docs#executor-policy-specification) for more information on approaches to policy provider.

Currently there's no scaffolding for multiple policy providers. The default config policy provider is built in. We need to add support for a policy plugin to be specified and selected. We also need to expand the policy provider plugin 

## Policy Provider Scaffolding

- Add policy provider factory to allow providers to be created and registered
- Add factory Create method to be implemented by each provider
    - Add Create method to existing configpolicy provider
- Add provider specific config to require provider specific fields
    - add `name` field to configpolicy provider config
- Add tests for factory

## Policy Provider API

Add a OverallVerifySuccess method to the interface. This will allow the policy provider implementation to interpret the verifier reports and make an overall determination. This method will accept the verifier reports list, which are one per reference verified. We will adapt the current `Verifier.VerifyResult` struct to include a `ArtifactType` field so we can easily filter and compare the artifact type of the reference verified in an individual verifier report.

```
type VerifierResult struct {
	Subject       string           `json:"subject,omitempty"`
	IsSuccess     bool             `json:"isSuccess,omitempty"`
	Name          string           `json:"name,omitempty"`
	Results       []string         `json:"results,omitempty"`
	NestedResults []VerifierResult `json:"nestedResults,omitempty"`
	ArtifactType  string           `json:"artifactType,omitempty"`
}
```

## Config Based Policy Provider

This is the current built in provider the executor uses. The config only supports ArtifactVerificationPolicies (a string map of artifact type to any/all policy defined)

```
...
    "policies": {
        "version": "1.0.0",
        "artifactVerificationPolicies": {
            "application/vnd.cncf.notary.v2.signature": "any",
            "org.example.sbom.v0": "all",
            "application/vnd.ratify.spdx.v0": "any"
        }
    }
...
```

'any' = check that at least one of the artifacts of the specified type verifies successfully
'all' = all artifacts of the specified type must verify successfully

### Current Supported Methods

- `VerifyNeeded(ctx context.Context, subjectReference common.Reference, referenceDesc ocispecs.ReferenceDescriptor)`
    - Can be used to verify that a subject should be verified
    - Can be used to verify that a reference to a subject should be verified
    - Currently returns true by default

- `ContinueVerifyOnFailure(ctx context.Context, subjectReference common.Reference, referenceDesc ocispecs.ReferenceDescriptor, partialVerifyResult types.VerifyResult)`
    - determines if executor should continue to verify if a reference artifact's verifier report is false
    - utilizes the `artifactVerificationPolicies` to determine continuation

- `ErrorToVerifyResult(ctx context.Context, subjectRefString string, verifyError error)`
    - returns a verifier result based on error provided

### Proposed Additions
- `OverallVerifyResult(ctx context.Context, verifierReports []interface{})`
    - returns an overall success value based on all verifier reports and the `artifactVerificationPolicies`

### New Config Sample

```
...
    "policies": {
        "version": "1.0.0",
        "policyPlugin": {
            "name": "configPolicy",
            "artifactVerificationPolicies": {
                "application/vnd.cncf.notary.v2.signature": "any",
                "org.example.sbom.v0": "all",
                "application/vnd.ratify.spdx.v0": "any"
            }
        }
    }
...
```

## OPA Policy Provider

The OPA Policy Provider implementation will require an OPA rego file to be specified. For each of the API methods, it will make a specific query to OPA with the function parameters as input. OPA will evaluate the query using the input json and the rego to return a boolean. 

### Sample Config file
```
...
    "policies": {
        "version": "1.0.0",
        "policyPlugin": {
            "name": "OPAPolicy",
            "regoFilePath": "path/to/rego"
        }
    }
...
```

          
