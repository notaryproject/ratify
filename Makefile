BINARY_NAME		= ratify
INSTALL_DIR		= ~/.ratify
CERT_DIR        = ${GITHUB_WORKSPACE}/tls/certs

GO_PKG			= github.com/deislabs/ratify
GIT_COMMIT_HASH = $(shell git rev-parse HEAD)
GIT_TREE_STATE 	= $(shell test -n "`git status --porcelain`" && echo "modified" || echo "unmodified")
GIT_TAG     	= $(shell git describe --tags --abbrev=0 --exact-match 2>/dev/null)

LDFLAGS = -w
LDFLAGS += -X $(GO_PKG)/internal/version.GitCommitHash=$(GIT_COMMIT_HASH)
LDFLAGS += -X $(GO_PKG)/internal/version.GitTreeState=$(GIT_TREE_STATE)
LDFLAGS += -X $(GO_PKG)/internal/version.GitTag=$(GIT_TAG)

KIND_VERSION ?= 0.14.0
KUBERNETES_VERSION ?= 1.31.2
GATEKEEPER_VERSION ?= 3.11.0
COSIGN_VERSION ?= 1.13.1
NOTATION_VERSION ?= 1.0.0-rc.3
ORAS_VERSION ?= 1.0.0-rc.2

HELM_VERSION ?= 3.9.2
BATS_TESTS_FILE ?= test/bats/test.bats
BATS_CLI_TESTS_FILE ?= test/bats/cli-test.bats
BATS_VERSION ?= 1.7.0
SYFT_VERSION ?= v1.44.0
TRIVY_VERSION ?= 0.71.0
ALPINE_IMAGE ?= alpine@sha256:93d5a28ff72d288d69b5997b8ba47396d2cbb62a72b5d87cd3351094b5d578a0

# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
ENVTEST_K8S_VERSION = 1.24.2

GATEKEEPER_NAMESPACE = gatekeeper-system
RATIFY_NAME = ratify

# Local Registry Setup
LOCAL_REGISTRY_IMAGE ?= ghcr.io/oras-project/registry:v1.0.0-rc.4
LOCAL_UNSIGNED_IMAGE = hello-world:latest
TEST_REGISTRY = localhost:5000
TEST_REGISTRY_USERNAME = test_user
TEST_REGISTRY_PASSWORD = test_pw
IS_OCI_1_1 ?= true

all: build test

.PHONY: build
build: build-cli build-plugins

.PHONY: build-cli
build-cli: fmt vet
	go build --ldflags="$(LDFLAGS)" -cover \
	-coverpkg=github.com/deislabs/ratify/pkg/...,github.com/deislabs/ratify/config/...,github.com/deislabs/ratify/cmd/... \
	-o ./bin/${BINARY_NAME} ./cmd/${BINARY_NAME}

.PHONY: build-plugins
build-plugins:
	go build -cover -coverpkg=github.com/deislabs/ratify/plugins/verifier/cosign/... -o ./bin/plugins/ ./plugins/verifier/cosign
	go build -cover -coverpkg=github.com/deislabs/ratify/plugins/verifier/licensechecker/... -o ./bin/plugins/ ./plugins/verifier/licensechecker
	go build -cover -coverpkg=github.com/deislabs/ratify/plugins/verifier/sample/... -o ./bin/plugins/ ./plugins/verifier/sample
	go build -cover -coverpkg=github.com/deislabs/ratify/plugins/verifier/sbom/... -o ./bin/plugins/ ./plugins/verifier/sbom
	go build -cover -coverpkg=github.com/deislabs/ratify/plugins/verifier/schemavalidator/... -o ./bin/plugins/ ./plugins/verifier/schemavalidator

.PHONY: install
install:
	mkdir -p ${INSTALL_DIR}
	mkdir -p ${INSTALL_DIR}/ratify-certs/cosign
	mkdir -p ${INSTALL_DIR}/ratify-certs/notary
	cp -r ./bin/* ${INSTALL_DIR}

.PHONY: ratify-config
ratify-config:
	cp ./test/bats/tests/config/* ${INSTALL_DIR}
	cp ./test/bats/tests/certificates/wabbit-networks.io.crt ${INSTALL_DIR}/ratify-certs/notary/wabbit-networks.io.crt
	cp ./test/bats/tests/certificates/cosign.pub ${INSTALL_DIR}/ratify-certs/cosign/cosign.pub
	cp -r ./test/bats/tests/schemas/ ${INSTALL_DIR}
	
.PHONY: test
test:
	go test -v -coverprofile=coverage.txt -covermode=atomic ./...

.PHONY: clean
clean:
	go clean
	rm ./bin/${BINARY_NAME}

.PHONY: deploy-demo
deploy-demo: deploy-gatekeeper deploy-ratify deploy-demo-constraints

.PHONY: delete-demo
delete-demo: delete-demo-constraints delete-ratify delete-gatekeeper

.PHONY: deploy-ratify
deploy-ratify:
	helm install ratify ./charts/ratify --atomic

.PHONY: delete-ratify
delete-ratify:
	helm delete ratify

.PHONY: deploy-demo-constraints
deploy-demo-constraints:
	kubectl apply -f ./library/default/template.yaml
	kubectl apply -f ./library/default/samples/constraint.yaml

.PHONY: delete-demo-constraints
delete-demo-constraints:
	kubectl delete -f ./library/default/template.yaml
	kubectl delete -f ./library/default/samples/constraint.yaml

.PHONY: deploy-gatekeeper
deploy-gatekeeper:
	helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
	helm install gatekeeper/gatekeeper  \
		--version ${GATEKEEPER_VERSION} \
		--name-template=gatekeeper \
		--namespace ${GATEKEEPER_NAMESPACE} --create-namespace \
	    --set enableExternalData=true

.PHONY: delete-gatekeeper
delete-gatekeeper:
	helm delete gatekeeper --namespace ${GATEKEEPER_NAMESPACE}

.PHONY: test-e2e
test-e2e: generate-rotation-certs
	bats -t ${BATS_TESTS_FILE}

.PHONY: test-e2e-cli
test-e2e-cli: e2e-dependencies e2e-create-local-registry e2e-notaryv2-setup e2e-notation-leaf-cert-setup e2e-cosign-setup e2e-licensechecker-setup e2e-sbom-setup e2e-schemavalidator-setup
	rm ${GOCOVERDIR} -rf
	mkdir ${GOCOVERDIR} -p
	IS_OCI_1_1=${IS_OCI_1_1} RATIFY_DIR=${INSTALL_DIR} TEST_REGISTRY=${TEST_REGISTRY} ${GITHUB_WORKSPACE}/bin/bats -t ${BATS_CLI_TESTS_FILE}
	go tool covdata textfmt -i=${GOCOVERDIR} -o test/e2e/coverage.txt

.PHONY: generate-certs
generate-certs:
	./scripts/generate-tls-certs.sh ${CERT_DIR} ${GATEKEEPER_NAMESPACE}

generate-rotation-certs:
	mkdir -p .staging/rotation
	mkdir -p .staging/rotation/gatekeeper

	./scripts/generate-gk-tls-certs.sh .staging/rotation/gatekeeper ${GATEKEEPER_NAMESPACE}
	./scripts/generate-tls-certs.sh .staging/rotation ${GATEKEEPER_NAMESPACE}

install-bats:
	# Download and install bats
	curl -sSLO https://github.com/bats-core/bats-core/archive/v${BATS_VERSION}.tar.gz && tar -zxvf v${BATS_VERSION}.tar.gz && bash bats-core-${BATS_VERSION}/install.sh ${GITHUB_WORKSPACE}

e2e-dependencies:
	# Download and install kind
	curl -L https://github.com/kubernetes-sigs/kind/releases/download/v${KIND_VERSION}/kind-linux-amd64 --output ${GITHUB_WORKSPACE}/bin/kind && chmod +x ${GITHUB_WORKSPACE}/bin/kind
	# Download and install kubectl
	curl -fsSL https://dl.k8s.io/release/v${KUBERNETES_VERSION}/bin/linux/amd64/kubectl --output ${GITHUB_WORKSPACE}/bin/kubectl && chmod +x ${GITHUB_WORKSPACE}/bin/kubectl
	# Download and install bats
	curl -sSLO https://github.com/bats-core/bats-core/archive/v${BATS_VERSION}.tar.gz && tar -zxvf v${BATS_VERSION}.tar.gz && bash bats-core-${BATS_VERSION}/install.sh ${GITHUB_WORKSPACE}
	# Download and install jq
	curl -L https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 --output ${GITHUB_WORKSPACE}/bin/jq && chmod +x ${GITHUB_WORKSPACE}/bin/jq
	# Install ORAS
	curl -LO https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_amd64.tar.gz
	mkdir -p oras-install/
	tar -zxf oras*.tar.gz -C oras-install/
	mv oras-install/oras ${GITHUB_WORKSPACE}/bin
	rm -rf oras*.tar.gz oras-install/

KIND_NODE_VERSION := kindest/node:v$(KUBERNETES_VERSION)

e2e-create-local-registry: e2e-run-local-registry e2e-create-all-image

e2e-run-local-registry:
	rm -rf ~/auth
	mkdir ~/auth
	docker run --entrypoint htpasswd httpd@sha256:dd993a2108430ec8fdc4942f791ccf9b0c7a6df196907a80e7e8a5f8f1bbf678 -Bbn ${TEST_REGISTRY_USERNAME} ${TEST_REGISTRY_PASSWORD}> ~/auth/htpasswd

	if [ "$$(docker inspect -f '{{.State.Running}}' "registry" 2>/dev/null || true)" ]; then docker stop registry && docker rm registry; fi
	docker pull ${LOCAL_REGISTRY_IMAGE}
	docker run -d \
		-p 5000:5000 \
		--restart=always \
		--name registry \
		-v ${HOME}/auth:/auth \
		-e "REGISTRY_AUTH=htpasswd" \
		-e "REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm" \
		-e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd \
		-e REGISTRY_STORAGE_DELETE_ENABLED=true \
		${LOCAL_REGISTRY_IMAGE}
	sleep 5
	docker login -u ${TEST_REGISTRY_USERNAME} -p ${TEST_REGISTRY_PASSWORD} ${TEST_REGISTRY}
	${GITHUB_WORKSPACE}/bin/oras login \
		-u ${TEST_REGISTRY_USERNAME} \
		-p ${TEST_REGISTRY_PASSWORD} \
		${TEST_REGISTRY}

e2e-create-all-image:
	rm -rf .staging
	mkdir .staging
	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "all-in-one image"]' > .staging/Dockerfile
	docker build --no-cache -t ${TEST_REGISTRY}/all:v0 .staging
	docker push ${TEST_REGISTRY}/all:v0

e2e-bootstrap: e2e-dependencies e2e-create-local-registry
	printf 'kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\ncontainerdConfigPatches:\n- |-\n  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:5000"]\n    endpoint = ["http://registry:5000"]' > kind_config.yaml

	# Check for existing kind cluster
	if [ $$(${GITHUB_WORKSPACE}/bin/kind get clusters) ]; then ${GITHUB_WORKSPACE}/bin/kind delete cluster; fi
	# Create a new kind cluster
	TERM=dumb ${GITHUB_WORKSPACE}/bin/kind create cluster --image $(KIND_NODE_VERSION) --wait 5m --config=kind_config.yaml
	if [ "$$(docker inspect -f='{{json .NetworkSettings.Networks.kind}}' "registry")" = 'null' ]; then docker network connect "kind" "registry"; fi
	rm kind_config.yaml

e2e-helm-install:
	rm -rf .staging/helm
	mkdir -p .staging/helm
	curl https://get.helm.sh/helm-v${HELM_VERSION}-linux-amd64.tar.gz --output .staging/helm/helmbin.tar.gz
	cd .staging/helm && tar -xvf helmbin.tar.gz
	./.staging/helm/linux-amd64/helm version --client

e2e-docker-credential-store-setup:
	rm -rf .staging/pass
	mkdir -p .staging/pass
	cd .staging/pass && git clone https://github.com/docker/docker-credential-helpers.git
	cd .staging/pass/docker-credential-helpers && make pass
	cp .staging/pass/docker-credential-helpers/bin/build/docker-credential-pass /usr/local/bin/
	sed -i '0,/{/s/{/{\n\t"credsStore": "pass",/' ~/.docker/config.json

	gpg --batch --passphrase '' --quick-gen-key ratify default default
	pass init $$(gpg --list-keys ratify | sed -n 2p | tr -d " \t\n\r")

e2e-notaryv2-setup:
	rm -rf .staging/notaryv2
	mkdir -p .staging/notaryv2
	curl -L https://github.com/notaryproject/notation/releases/download/v${NOTATION_VERSION}/notation_${NOTATION_VERSION}_linux_amd64.tar.gz --output ${GITHUB_WORKSPACE}/.staging/notaryv2/notation.tar.gz
	tar -zxvf ${GITHUB_WORKSPACE}/.staging/notaryv2/notation.tar.gz -C ${GITHUB_WORKSPACE}/.staging/notaryv2

	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "notaryv2 signed image"]' > .staging/notaryv2/Dockerfile
	docker build --no-cache -t ${TEST_REGISTRY}/notation:signed .staging/notaryv2
	docker push ${TEST_REGISTRY}/notation:signed

	docker pull ${LOCAL_UNSIGNED_IMAGE}
	docker image tag ${LOCAL_UNSIGNED_IMAGE} ${TEST_REGISTRY}/notation:unsigned
	docker push ${TEST_REGISTRY}/notation:unsigned

	rm -rf ~/.config/notation
	.staging/notaryv2/notation cert generate-test --default "ratify-bats-test"

	.staging/notaryv2/notation sign -u ${TEST_REGISTRY_USERNAME} -p ${TEST_REGISTRY_PASSWORD} `docker image inspect ${TEST_REGISTRY}/notation:signed | jq -r .[0].RepoDigests[0]`
	.staging/notaryv2/notation sign -u ${TEST_REGISTRY_USERNAME} -p ${TEST_REGISTRY_PASSWORD} `docker image inspect ${TEST_REGISTRY}/all:v0 | jq -r .[0].RepoDigests[0]`

	# OCI 1.1 Artifact Resources
	if [ ${IS_OCI_1_1} = 'true' ]; then \
		printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "notaryv2 signed image oci artifact"]' > .staging/notaryv2/Dockerfile && \
		docker build --no-cache -t ${TEST_REGISTRY}/notation:ociartifact .staging/notaryv2 && \
		docker push ${TEST_REGISTRY}/notation:ociartifact && \
		.staging/notaryv2/notation sign --signature-manifest artifact -u ${TEST_REGISTRY_USERNAME} -p ${TEST_REGISTRY_PASSWORD} `docker image inspect ${TEST_REGISTRY}/notation:ociartifact | jq -r .[0].RepoDigests[0]`; \
	fi

e2e-notation-leaf-cert-setup:
	mkdir -p .staging/notaryv2/leaf-test
	mkdir -p ~/.config/notation/truststore/x509/ca/leaf-test
	./scripts/generate-cert-chain.sh .staging/notaryv2/leaf-test
	cp .staging/notaryv2/leaf-test/leaf.crt ~/.config/notation/truststore/x509/ca/leaf-test/leaf.crt
	cp .staging/notaryv2/leaf-test/ca.crt ~/.config/notation/truststore/x509/ca/leaf-test/root.crt
	cat .staging/notaryv2/leaf-test/ca.crt >> .staging/notaryv2/leaf-test/leaf.crt

	jq '.keys += [{"name":"leaf-test","keyPath":".staging/notaryv2/leaf-test/leaf.key","certPath":".staging/notaryv2/leaf-test/leaf.crt"}]' ~/.config/notation/signingkeys.json > tmp && mv tmp ~/.config/notation/signingkeys.json

	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "notaryv2 leaf signed image"]' > .staging/notaryv2/Dockerfile
	docker build --no-cache -t ${TEST_REGISTRY}/notation:leafSigned .staging/notaryv2
	docker push ${TEST_REGISTRY}/notation:leafSigned
	.staging/notaryv2/notation sign -u ${TEST_REGISTRY_USERNAME} -p ${TEST_REGISTRY_PASSWORD} --key "leaf-test" `docker image inspect ${TEST_REGISTRY}/notation:leafSigned | jq -r .[0].RepoDigests[0]`

e2e-cosign-setup:
	rm -rf .staging/cosign
	mkdir -p .staging/cosign
	curl -sSLO https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64
	mv cosign-linux-amd64 .staging/cosign
	chmod +x .staging/cosign/cosign-linux-amd64

	# image signed with a key
	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "cosign signed image"]' > .staging/cosign/Dockerfile
	docker build --no-cache -t ${TEST_REGISTRY}/cosign:signed-key .staging/cosign
	docker push ${TEST_REGISTRY}/cosign:signed-key

	docker pull ${LOCAL_UNSIGNED_IMAGE}
	docker image tag ${LOCAL_UNSIGNED_IMAGE} ${TEST_REGISTRY}/cosign:unsigned
	docker push ${TEST_REGISTRY}/cosign:unsigned

	export COSIGN_PASSWORD="test" && \
	cd .staging/cosign && \
	./cosign-linux-amd64 login ${TEST_REGISTRY} -u ${TEST_REGISTRY_USERNAME} -p ${TEST_REGISTRY_PASSWORD} && \
	./cosign-linux-amd64 generate-key-pair && \
	./cosign-linux-amd64 sign --key cosign.key `docker image inspect ${TEST_REGISTRY}/cosign:signed-key | jq -r .[0].RepoDigests[0]` && \
	./cosign-linux-amd64 sign --key cosign.key `docker image inspect ${TEST_REGISTRY}/all:v0 | jq -r .[0].RepoDigests[0]`

e2e-licensechecker-setup:
	rm -rf .staging/licensechecker
	mkdir -p .staging/licensechecker

	# Install Syft
	curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b .staging/licensechecker ${SYFT_VERSION}

	# Build/Push Image
	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "licensechecker image"]' > .staging/licensechecker/Dockerfile
	docker build --no-cache -t ${TEST_REGISTRY}/licensechecker:v0 .staging/licensechecker
	docker push ${TEST_REGISTRY}/licensechecker:v0

	# Create/Attach SPDX
	.staging/licensechecker/syft -o spdx --file .staging/licensechecker/sbom.spdx ${TEST_REGISTRY}/licensechecker:v0
	${GITHUB_WORKSPACE}/bin/oras attach ${TEST_REGISTRY}/licensechecker:v0 \
  		--artifact-type application/vnd.ratify.spdx.v0 \
  		.staging/licensechecker/sbom.spdx:application/text
	${GITHUB_WORKSPACE}/bin/oras attach ${TEST_REGISTRY}/all:v0 \
  		--artifact-type application/vnd.ratify.spdx.v0 \
  		.staging/licensechecker/sbom.spdx:application/text

	# OCI 1.1 Artifact Resources
	if [ ${IS_OCI_1_1} = 'true' ]; then \
		printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "licensechecker image oci artifact"]' > .staging/licensechecker/Dockerfile && \
		docker build -t ${TEST_REGISTRY}/licensechecker:ociartifact .staging/licensechecker && \
		docker push ${TEST_REGISTRY}/licensechecker:ociartifact && \
		${GITHUB_WORKSPACE}/bin/oras attach ${TEST_REGISTRY}/licensechecker:ociartifact \
			--artifact-type application/vnd.ratify.spdx.v0 \
			--image-spec v1.1-artifact \
			.staging/licensechecker/sbom.spdx:application/text; \
	fi

e2e-sbom-setup:
	rm -rf .staging/sbom
	mkdir -p .staging/sbom

	# Install sbom-tool
	curl -Lo .staging/sbom/sbom-tool https://github.com/microsoft/sbom-tool/releases/latest/download/sbom-tool-linux-x64 && chmod +x .staging/sbom/sbom-tool

	# Build/Push Images
	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "sbom image"]' > .staging/sbom/Dockerfile
	docker build --no-cache -t ${TEST_REGISTRY}/sbom:v0 .staging/sbom
	docker push ${TEST_REGISTRY}/sbom:v0
	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "sbom image unsigned"]' > .staging/sbom/Dockerfile
	docker build --no-cache -t ${TEST_REGISTRY}/sbom:unsigned .staging/sbom
	docker push ${TEST_REGISTRY}/sbom:unsigned

	# Generate/Attach sbom
	.staging/sbom/sbom-tool generate -b .staging/sbom -bc . -pn ratify -m .staging/sbom -pv 1.0 -ps acme -nsu ratify -nsb http://registry:5000 -D true
	${GITHUB_WORKSPACE}/bin/oras attach \
		--artifact-type org.example.sbom.v0 \
		 ${TEST_REGISTRY}/sbom:v0 \
		.staging/sbom/_manifest/spdx_2.2/manifest.spdx.json:application/spdx+json
	${GITHUB_WORKSPACE}/bin/oras attach \
		--artifact-type org.example.sbom.v0 \
		 ${TEST_REGISTRY}/sbom:unsigned \
		.staging/sbom/_manifest/spdx_2.2/manifest.spdx.json:application/spdx+json
	${GITHUB_WORKSPACE}/bin/oras attach \
		--artifact-type org.example.sbom.v0 \
		 ${TEST_REGISTRY}/all:v0 \
		.staging/sbom/_manifest/spdx_2.2/manifest.spdx.json:application/spdx+json

	# Push Signature to sbom
	.staging/notaryv2/notation sign -u ${TEST_REGISTRY_USERNAME} -p ${TEST_REGISTRY_PASSWORD} ${TEST_REGISTRY}/sbom@`oras discover -o json --artifact-type org.example.sbom.v0 ${TEST_REGISTRY}/sbom:v0 | jq -r ".manifests[0].digest"`
	.staging/notaryv2/notation sign -u ${TEST_REGISTRY_USERNAME} -p ${TEST_REGISTRY_PASSWORD} ${TEST_REGISTRY}/all@`oras discover -o json --artifact-type org.example.sbom.v0 ${TEST_REGISTRY}/all:v0 | jq -r ".manifests[0].digest"` 

	# OCI 1.1 Artifact Resources
	if [ ${IS_OCI_1_1} = 'true' ]; then \
		printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "sbom image oci artifact"]' > .staging/sbom/Dockerfile && \
		docker build --no-cache -t ${TEST_REGISTRY}/sbom:ociartifact .staging/sbom && \
		docker push ${TEST_REGISTRY}/sbom:ociartifact && \
		${GITHUB_WORKSPACE}/bin/oras attach \
			--artifact-type org.example.sbom.v0 \
			--image-spec v1.1-artifact \
			 ${TEST_REGISTRY}/sbom:ociartifact \
			.staging/sbom/_manifest/spdx_2.2/manifest.spdx.json:application/spdx+json && \
		.staging/notaryv2/notation sign --signature-manifest artifact -u ${TEST_REGISTRY_USERNAME} -p ${TEST_REGISTRY_PASSWORD} ${TEST_REGISTRY}/sbom@`oras discover -o json --artifact-type org.example.sbom.v0 ${TEST_REGISTRY}/sbom:ociartifact | jq -r ".manifests[0].digest"`; \
	fi

e2e-schemavalidator-setup:
	rm -rf .staging/schemavalidator
	mkdir -p .staging/schemavalidator

	# Install Trivy
	curl -fsSL https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz --output .staging/schemavalidator/trivy.tar.gz
	tar -zxf .staging/schemavalidator/trivy.tar.gz -C .staging/schemavalidator

	# Build/Push Images
	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "schemavalidator image"]' > .staging/schemavalidator/Dockerfile
	docker build --no-cache -t ${TEST_REGISTRY}/schemavalidator:v0 .staging/schemavalidator
	docker push ${TEST_REGISTRY}/schemavalidator:v0

	# Create/Attach Scan Results
	.staging/schemavalidator/trivy image --format sarif --output .staging/schemavalidator/trivy-scan.sarif ${TEST_REGISTRY}/schemavalidator:v0
	${GITHUB_WORKSPACE}/bin/oras attach \
		--artifact-type vnd.aquasecurity.trivy.report.sarif.v1 \
		${TEST_REGISTRY}/schemavalidator:v0 \
		.staging/schemavalidator/trivy-scan.sarif:application/sarif+json
	${GITHUB_WORKSPACE}/bin/oras attach \
		--artifact-type vnd.aquasecurity.trivy.report.sarif.v1 \
		${TEST_REGISTRY}/all:v0 \
		.staging/schemavalidator/trivy-scan.sarif:application/sarif+json
	
	# OCI 1.1 Artifact Resources
	if [ ${IS_OCI_1_1} = 'true' ]; then \
		printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "schemavalidator image oci artifact"]' > .staging/schemavalidator/Dockerfile && \
		docker build --no-cache -t ${TEST_REGISTRY}/schemavalidator:ociartifact .staging/schemavalidator && \
		docker push ${TEST_REGISTRY}/schemavalidator:ociartifact && \
		${GITHUB_WORKSPACE}/bin/oras attach \
			--artifact-type vnd.aquasecurity.trivy.report.sarif.v1 \
			${TEST_REGISTRY}/schemavalidator:ociartifact \
			--image-spec v1.1-artifact \
			.staging/schemavalidator/trivy-scan.sarif:application/sarif+json; \
	fi

e2e-inlinecert-setup:
	rm -rf .staging/inlinecert
	mkdir -p .staging/inlinecert

	# build and sign an image with an alternate certificate
	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "alternate notaryv2 signed image"]' > .staging/inlinecert/Dockerfile
	docker build --no-cache -t ${TEST_REGISTRY}/notation:signed-alternate .staging/inlinecert
	docker push ${TEST_REGISTRY}/notation:signed-alternate

	.staging/notaryv2/notation cert generate-test "alternate-cert"
	.staging/notaryv2/notation sign -u ${TEST_REGISTRY_USERNAME} -p ${TEST_REGISTRY_PASSWORD} --key "alternate-cert" `docker image inspect ${TEST_REGISTRY}/notation:signed-alternate | jq -r .[0].RepoDigests[0]`

e2e-azure-setup: e2e-create-all-image e2e-notaryv2-setup e2e-notation-leaf-cert-setup e2e-cosign-setup e2e-licensechecker-setup e2e-sbom-setup e2e-schemavalidator-setup

e2e-deploy-gatekeeper: e2e-helm-install
	./.staging/helm/linux-amd64/helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
	./.staging/helm/linux-amd64/helm install gatekeeper/gatekeeper  \
	--version ${GATEKEEPER_VERSION} \
    --name-template=gatekeeper \
    --namespace ${GATEKEEPER_NAMESPACE} --create-namespace \
    --set enableExternalData=true \
    --set validatingWebhookTimeoutSeconds=5 \
    --set mutatingWebhookTimeoutSeconds=2 \
    --set auditInterval=0

e2e-deploy-ratify: e2e-notaryv2-setup e2e-notation-leaf-cert-setup e2e-cosign-setup e2e-cosign-setup e2e-licensechecker-setup e2e-sbom-setup e2e-schemavalidator-setup e2e-inlinecert-setup
	docker build --progress=plain --no-cache -f ./httpserver/Dockerfile -t localbuild:test .
	kind load docker-image --name kind localbuild:test

	docker build --progress=plain --no-cache --build-arg KUBE_VERSION=${KUBERNETES_VERSION} --build-arg TARGETOS="linux" --build-arg TARGETARCH="amd64" -f crd.Dockerfile -t localbuildcrd:test ./charts/ratify/crds
	kind load docker-image --name kind localbuildcrd:test

	printf "{\n\t\"auths\": {\n\t\t\"registry:5000\": {\n\t\t\t\"auth\": \"`echo "${TEST_REGISTRY_USERNAME}:${TEST_REGISTRY_PASSWORD}" | tr -d '\n' | base64 -i -w 0`\"\n\t\t}\n\t}\n}" > mount_config.json

	./.staging/helm/linux-amd64/helm install ${RATIFY_NAME} \
    ./charts/ratify --atomic --namespace ${GATEKEEPER_NAMESPACE} --create-namespace \
	--set image.repository=localbuild \
	--set image.crdRepository=localbuildcrd \
	--set image.tag=test \
	--set gatekeeper.version=${GATEKEEPER_VERSION} \
	--set-file provider.tls.crt=${CERT_DIR}/server.crt \
	--set-file provider.tls.key=${CERT_DIR}/server.key \
	--set provider.tls.cabundle="$(shell cat ${CERT_DIR}/ca.crt | base64 | tr -d '\n')" \
	--set notaryCert="$$(cat ~/.config/notation/localkeys/ratify-bats-test.crt)" \
	--set cosign.key="$$(cat .staging/cosign/cosign.pub)" \
	--set oras.useHttp=true \
	--set-file dockerConfig="mount_config.json" \
	--set logLevel=debug

	rm mount_config.json
e2e-aks:
	./scripts/azure-ci-test.sh ${KUBERNETES_VERSION} ${GATEKEEPER_VERSION} ${TENANT_ID} ${GATEKEEPER_NAMESPACE} ${CERT_DIR}

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen conversion-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations. Also generate conversions between structs of different API versions.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."
	$(CONVERSION_GEN) \
        --input-dirs "./api/v1beta1,./api/v1alpha1" \
        --go-header-file "./hack/boilerplate.go.txt" \
        --output-file-base "zz_generated.conversion"

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install-crds
install-crds: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

.PHONY: uninstall-crds
uninstall-crds: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default | kubectl apply -f -

.PHONY: undeploy
undeploy: ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/default | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

##@ Build Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
CONVERSION_GEN ?= $(LOCALBIN)/conversion-gen

## Tool Versions
KUSTOMIZE_VERSION ?= v3.8.7
CONTROLLER_TOOLS_VERSION ?= v0.9.2
CONVERSION_TOOLS_VERSION ?= v0.26.1

KUSTOMIZE_INSTALL_SCRIPT ?= "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"
.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	test -s $(LOCALBIN)/kustomize || { curl -s $(KUSTOMIZE_INSTALL_SCRIPT) | bash -s -- $(subst v,,$(KUSTOMIZE_VERSION)) $(LOCALBIN); }

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	test -s $(LOCALBIN)/controller-gen || GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: conversion-gen
conversion-gen: $(CONVERSION_GEN) ## Download conversion-gen locally if necessary.
$(CONVERSION_GEN): $(LOCALBIN)
	test -s $(LOCALBIN)/conversion-gen || GOBIN=$(LOCALBIN) go install k8s.io/code-generator/cmd/conversion-gen@$(CONVERSION_TOOLS_VERSION)
