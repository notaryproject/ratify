# Contributing to Ratify

Welcome! We are very happy to accept community contributions to Ratify, whether those are [Pull Requests](#pull-requests), [Plugins](#plugins), [Feature Suggestions](#feature-suggestions) or [Bug Reports](#bug-reports)! Please note that by participating in this project, you agree to abide by the [Code of Conduct](./CODE_OF_CONDUCT.md), as well as the terms of the [CLA](#cla).

## Table of Contents
- [Getting Started](#getting-started)
- [Feature Areas](#feature-areas)
- [Feature Enhancements](#feature-enhancements)
- [Feature Suggestions](#feature-suggestions)
- [Bug Reports](#bug-reports)
- [Developing](#developing)
- [Pull Requests](#pull-requests)

## Getting Started

* If you don't already have it, you will need [go](https://golang.org/dl/) v1.16+ installed locally to build the project.
* You can work on Ratify using any platform using any editor, but you may find it quickest to get started using [VSCode](https://code.visualstudio.com/Download) with the [Go extension](https://marketplace.visualstudio.com/items?itemName=golang.Go).
* Fork this repo (see [this forking guide](https://guides.github.com/activities/forking/) for more information).
* Checkout the repo locally with `git clone git@github.com:{your_username}/ratify.git`.
* Build the Ratify CLI with `go build -o ./bin/ratify ./cmd/ratify` or if on Mac/Linux/WSL `make build-cli`.

## Feature Enhancements
For non-trivial enhancements or bug fixes, please start by raising a document PR. You can refer to the example [here](https://github.com/ratify-project/ratify/blame/dev/docs/proposals/Release-Supply-Chain-Metadata.md).
Major user experience updates should be documented in [/doc/proposals](https://github.com/ratify-project/ratify/tree/dev/docs/proposals). Changes to technical implementation should be added to [/doc/design](https://github.com/ratify-project/ratify/tree/dev/docs/design).  

Consider adding the following section where applicable:
- Proposed changes
- Proposed feature flag
- Impacted code paths
- Required test coverage
- Backward compatibility
- Performance impact
- Security consideration
- Open questions
  
This approach ensures that the changes are well-documented and reviewed before implementation.

## Pull Requests

If you'd like to start contributing to Ratify, you can search for issues tagged as "good first issue" [here](https://github.com/ratify-project/ratify/labels/good%20first%20issue).

We use the `dev` branch as our default branch. PRs passing the basic set of validation can be merged to the `dev` branch, we then run the full suite of validation including cloud-specific tests on `dev` before changes can be merged into `main`. All ratify releases are cut from the `main` branch. A sample PR process is outlined below:
1. Fork this repo and create your dev branch from the default `dev` branch.
2. Create a PR against the default branch.
3. Add new unit test and [e2e test](https://github.com/ratify-project/ratify/tree/dev/test/bats) where appropriate.
4. Maintainer approval and e2e test validation is required for completing the PR.
5. On PR complete, the `push` event will trigger an automated PR targeting the `main` branch where we run a full suite validation including cloud-specific tests.
6. Manual merge is required to complete the PR. (**Please keep individual commits to maintain commit history**)

If the PR contains a regression that could not pass the full validation, please revert the change to unblock others:
1. Create a new dev branch based off `dev`.
2. Open a revert PR against `dev`.
3. Follow the same process to get this PR gets merged into `dev`.
4. Work on the fix and follow the above PR process.

### Commit

You should follow [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) to write commit message. As the Ratify Project repositories enforce the [DCO (Developer Certificate of Origin)](https://github.com/apps/dco) on Pull Requests, contributors are required to sign off that they adhere to those requirements by adding a `Signed-off-by` line to the commit messages. Git has even provided a `-s` command line option to append that automatically to your commit messages, please use it when you commit your changes. 

The Ratify Project repositories require signed commits, please refer to [SSH commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification#ssh-commit-signature-verification) on signing commits using SSH as it is easy to set up. You can find other methods to sign commits in the document [commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification). Git has provided a `-S` flag to create a signed commit.

An example of `git commit` command:

```shell
git commit -s -S -m <commit_message>
```

## Developing

### Components

The Ratify project is composed of the following main components:

* **Ratify CLI** (`cmd/ratify`): the `ratify` CLI executable.
* **Config** (`config`): an example configuration file for `ratify`.
* **Deploy** (`deploy`): the deployment files for using ratify in a Kubernetes cluster.
* **Ratify Internals** (`pkg`): the internal modules containing the majority of the Ratify code.
* **Plugins** (`plugins`): the referrer store and verifier plugins for the Ratify Framework.

### Running the tests

* You can use the following command to run the full Ratify test suite:
  * `go test -v ./cmd/ratify` on Windows
  * `make test` on Mac/Linux/WSL

### Running the Ratify CLI

* Once built run Ratify from the bin directory `./bin/ratify` for a list of the available commands.
* For any command the `--help` argument can be passed for more information and a list of possible arguments.

### Debugging Ratify with VS Code

Ratify can run through cli command or run as a http server. Create a [launch.json](https://code.visualstudio.com/docs/editor/debugging#_launch-configurations) file in the .vscode directory, then hit F5 to debug. Note the first debug session may take a few minutes to load, subsequent session will be much faster.
A demo of VS Code debugging experience is available from ratify community meeting [recording](https://youtu.be/o5ufkZRDiIg?si=mzSw5XHPxBJmgq8i&t=2793) min 46:33. 

Here is a sample json for cli. Note that for the following sample json to successfully work, you need to make sure that `verificationCerts` attribute of the verifier in your config file points to the notation verifier's certificate file. In order to do that, you can download the cert file with the following command:
`curl -sSLO https://raw.githubusercontent.com/deislabs/ratify/main/test/testdata/notation.crt`, 
and then modify the config file by setting the `verificationCerts` attribute in the notation verifier to the downloaded cert file path.

```json
{
    "version": "0.2.0",
    "configurations": [{
      "name": "Debug Ratify cli ",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "program": "${workspaceFolder}/cmd/ratify",
      "args": [
                "verify", 
                "-s", "ghcr.io/deislabs/ratify/notary-image:signed", 
                "-c", "${workspaceFolder}/test/bats/tests/config/config_cli.json"
      ]
    }]
}
```

Sample launch json for http server:

```json
{
    "version": "0.2.0",
    "configurations": [{
      "name": "Debug Ratify ",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "program": "${workspaceFolder}/cmd/ratify",
      "args": ["serve", "--http", ":6001", "-c", "/home/azureuser/.ratify/config.json"]
    }]
}
```

Sample curl request to invoke Ratify endpoint:

```bash
curl -X POST http://127.0.0.1:6001/ratify/gatekeeper/v1/verify -H "Content-Type: application/json" -d '{"apiVersion":"externaldata.gatekeeper.sh/v1alpha1","kind":"ProviderRequest","request":{"keys":["localhost:5000/net-monitor:v1"]}}'
```

#### Debug external plugins

External plugin processes must be attached in a separate debug session. Certain environment variables and `stdin` must be configured

Sample launch json for debugging a plugin:
```json
{
  "version": "0.2.0",
  "configurations": [{
    "name": "Debug SBOM Plugin",
    "type": "go",
    "request": "launch",
    "mode": "auto",
    "program": "${workspaceFolder}/plugins/verifier/sbom",
    "env": {
      "RATIFY_EXPERIMENTAL_DYNAMIC_PLUGINS": "1",
      "RATIFY_LOG_LEVEL": "debug",
      "RATIFY_VERIFIER_COMMAND": "VERIFY",
      "RATIFY_VERIFIER_SUBJECT": "wabbitnetworks.azurecr.io/test/image:sbom",
      "RATIFY_VERIFIER_VERSION": "1.0.0",
    },
    "console": "integratedTerminal"
  }]
}
```
Once session has started, paste the `json` formatted input config into the integrate terminal prompt.
Note: You can extract the exact JSON for the image/config you are testing with Ratify by starting a regular Ratify debug session. Inspect the `stdinData` parameter of the `ExecutePlugin` function [here](pkg/common/plugin/exec.go)

Sample JSON stdin 
```json
{
  "config": {
    "artifactTypes":"application/spdx+json",
    "name":"sbom",
    "disallowedLicenses":["AGPL"],
    "disallowedPackages":[{"name":"log4j-core","versionInfo":"2.13.0"}]
  },
  "storeConfig": {
    "version":"1.0.0",
    "pluginBinDirs":null,
    "store": {
      "name":"oras",
      "useHttp":true
    }
  },
  "referenceDesc": {
    "mediaType":"application/vnd.oci.image.manifest.v1+json",
    "digest":"sha256:...",
    "size":558,
    "artifactType":"application/spdx+json"
  }
}
```

Press `Ctrl+D` to send EOF character to terminate the stdin input. (Note: you may have to press `Ctrl+D` twice)

View more plugin debugging information [here](https://github.com/ratify-project/ratify-verifier-plugin#debugging-in-vs-code)

### Test local changes in the k8s cluster scenario

There are some changes that should be validated in a cluster scenario.
Follow the steps below to build and deploy a Ratify image with your private changes:

#### build an image with your local changes

```bash
export REGISTRY=yourregistry
docker buildx create --use

docker buildx build -f httpserver/Dockerfile --platform linux/amd64 --build-arg build_sbom=true --build-arg build_licensechecker=true --build-arg build_schemavalidator=true --build-arg build_vulnerabilityreport=true -t ${REGISTRY}/ratify-project/ratify:yourtag .
docker build --progress=plain --build-arg KUBE_VERSION="1.30.6" --build-arg TARGETOS="linux" --build-arg TARGETARCH="amd64" -f crd.Dockerfile -t ${REGISTRY}/localbuildcrd:yourtag ./charts/ratify/crds
```

#### [Authenticate](https://docs.docker.com/engine/reference/commandline/login/#usage) with your registry,  and push the newly built image

```bash
docker push ${REGISTRY}/ratify-project/ratify:yourtag
docker push ${REGISTRY}/localbuildcrd:yourtag
```

#### Update dev.helmfile.yaml
Replace Ratify `chart` and `version` with local values:
```yaml
...
chart: chart/ratify
version: <INSERT VERSION> # ATTENTION: Needs to match latest in Chart.yaml
...
```
Replace `repository`, `crdRepository`, and `tag` with previously built images:
```yaml
- name: image.repository 
  value: <YOUR RATIFY IMAGE REPOSITORY NAME>
- name: image.crdRepository
  value: <YOUR RATIFY CRD IMAGE REPOSITORY NAME>
- name: image.tag
  value: <YOUR IMAGES TAG NAME>
```

### Deploy using Dev Helmfile

Development charts + images are published weekly and latest versions are tagged with rolling tags referenced in dev helmfile.

Deploy to cluster:
```bash
helmfile sync -f git::https://github.com/ratify-project/ratify.git@dev.helmfile.yaml
```

### Deploy from local helm chart

#### Update [values.yaml](https://github.com/ratify-project/ratify/blob/main/charts/ratify/values.yaml) to pull from your registry, when reusing image tag, setting pull policy to "Always" ensures we are pull the new changes

```json
image:
  repository: yourregistry/ratify-project/ratify
  tag: yourtag
  pullPolicy: Always
```

Deploy using one of the following deployments.
Note: Ratify is compatible with Gatekeeper >= 3.12.0. Server auth is required to be enabled.

**Option 1**
Client auth disabled and server auth enabled using self signed certificate

```bash
helm install ratify ./charts/ratify --atomic
```

**Option 2**
Client auth disabled and server auth enabled using your own certificate

Deploy using a certificate

```bash
helm install ratify ./charts/ratify \
    --set provider.tls.cabundle="$(cat certs/ca.crt | base64 | tr -d '\n\r')" \
    --set provider.tls.key="$(cat certs/tls.key)" \
    --set provider.tls.crt="$(cat certs/tls.crt)" \
    --atomic
```

**Option 3**
Client / Server auth enabled (mTLS)  

>Note: Ratify and Gatekeeper must be installed in the same namespace which allows Ratify access to Gatekeepers CA certificate. The Ratify certificate must have a CN and subjectAltName name which matches the namespace of Gatekeeper and Ratify. For example, if installed to the namespace 'gatekeeper-system', the CN and subjectAltName should be 'ratify.gatekeeper-system'*

```bash
helm install ratify ./charts/ratify \
    --namespace gatekeeper-system \
    --set provider.tls.cabundle="$(cat certs/ca.crt | base64 | tr -d '\n\r')" \
    --set provider.tls.key="$(cat certs/tls.key)" \
    --set provider.tls.crt="$(cat certs/tls.crt)" \
    --atomic
```

## Feature Areas
### Plugins

If you'd like to contribute to the collection of plugins:

#### Referrer Store

* A referrer store should implement the `ReferrerStore` interface (`pkg/referrerstore/api.go`).
* This should provide a mechanism to list referrers, and retrieve manifests and blob content.
* A sample referrer store is provided at `plugins/reffererstore/sample/sample.go`.

#### Verifier

* A verifier should implement the `ReferenceVerifier` interface (`pkg/verifier/api.go`).
* This should provide a mechanism to perform verification against blobs and manifests from a referrer store.
* A sample verifier is provided at `plugins/verifier/sample/sample.go`.

## Feature Suggestions

* Please first search [Open Ratify Issues](https://github.com/ratify-project/ratify/issues) before opening an issue to check whether your feature has already been suggested. If it has, feel free to add your own comments to the existing issue.
* Ensure you have included a "What?" - what your feature entails, being as specific as possible, and giving mocked-up syntax examples where possible.
* Ensure you have included a "Why?" - what the benefit of including this feature will be.

## Bug Reports

* Please first search [Open Ratify Issues](https://github.com/ratify-project/ratify/issues) before opening an issue, to see if it has already been reported.
* Try to be as specific as possible, including the version of the Ratify CLI used to reproduce the issue, and any example arguments needed to reproduce it.
