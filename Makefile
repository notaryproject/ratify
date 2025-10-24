# Copyright The Ratify Authors.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
	  
BINARY_NAME		= ratify
INSTALL_DIR		= ~/.ratify
CERT_DIR        = ${GITHUB_WORKSPACE}/tls/certs

GO_PKG			= github.com/ratify-project/ratify
GIT_COMMIT_HASH = $(shell git rev-parse HEAD)
GIT_TREE_STATE 	= $(shell test -n "`git status --porcelain`" && echo "modified" || echo "unmodified")
GIT_TAG     	= $(shell git describe --tags --abbrev=0 --exact-match 2>/dev/null)

LDFLAGS = -w
LDFLAGS += -X $(GO_PKG)/internal/version.GitCommitHash=$(GIT_COMMIT_HASH)
LDFLAGS += -X $(GO_PKG)/internal/version.GitTreeState=$(GIT_TREE_STATE)
LDFLAGS += -X $(GO_PKG)/internal/version.GitTag=$(GIT_TAG)

KIND_VERSION ?= 0.25.0
KUBERNETES_VERSION ?= 1.34.1
KIND_KUBERNETES_VERSION ?= 1.34.0
GATEKEEPER_VERSION ?= 3.18.0
DAPR_VERSION ?= 1.14.4
COSIGN_VERSION ?= 2.4.1
NOTATION_VERSION ?= 1.2.0
ORAS_VERSION ?= 1.2.1

HELM_VERSION ?= 3.16.3
HELMFILE_VERSION ?= 0.169.2
BATS_BASE_TESTS_FILE ?= test/bats/base-test.bats
BATS_PLUGIN_TESTS_FILE ?= test/bats/plugin-test.bats
BATS_CLI_TESTS_FILE ?= test/bats/cli-test.bats
BATS_QUICKSTART_TESTS_FILE ?= test/bats/quickstart-test.bats
BATS_HA_TESTS_FILE ?= test/bats/high-availability.bats
BATS_VERSION ?= 1.11.1
SYFT_VERSION ?= v1.18.0
YQ_VERSION ?= v4.44.6
YQ_BINARY ?= yq_linux_amd64
ALPINE_IMAGE ?= alpine@sha256:93d5a28ff72d288d69b5997b8ba47396d2cbb62a72b5d87cd3351094b5d578a0
ALPINE_IMAGE_VULNERABLE ?= alpine@sha256:25fad2a32ad1f6f510e528448ae1ec69a28ef81916a004d3629874104f8a7f70
REDIS_IMAGE_TAG ?= 7.4-debian-12
CERT_ROTATION_ENABLED ?= false
REGO_POLICY_ENABLED ?= false
SBOM_TOOL_VERSION ?=v2.2.9
TRIVY_VERSION ?= 0.58.0

GATEKEEPER_NAMESPACE = gatekeeper-system
RATIFY_NAME = ratify

TIMESTAMP_URL = http://timestamp.digicert.com

# Local Registry Setup
LOCAL_REGISTRY_IMAGE ?= ghcr.io/project-zot/zot-linux-amd64:v2.0.2
TEST_REGISTRY = localhost:5000
TEST_REGISTRY_USERNAME = test_user
TEST_REGISTRY_PASSWORD = test_pw

# Azure Key Vault Setup
KEYVAULT_NAME ?= ratify-akv
KEYVAULT_KEY_NAME ?= test-key
AZURE_SP_OBJECT_ID ?= 00000000-0000-0000-0000-000000000000

all: build test

.PHONY: build
build: build-cli build-plugins

.PHONY: build-cli
build-cli: fmt vet
	go build --ldflags="$(LDFLAGS)" -cover \
	-coverpkg=github.com/ratify-project/ratify/pkg/...,github.com/ratify-project/ratify/config/...,github.com/ratify-project/ratify/cmd/... \
	-o ./bin/${BINARY_NAME} ./cmd/${BINARY_NAME}

.PHONY: build-plugins
build-plugins:
	go build -cover -coverpkg=github.com/ratify-project/ratify/plugins/verifier/licensechecker/... -o ./bin/plugins/ ./plugins/verifier/licensechecker
	go build -cover -coverpkg=github.com/ratify-project/ratify/plugins/verifier/sample/... -o ./bin/plugins/ ./plugins/verifier/sample
	go build -cover -coverpkg=github.com/ratify-project/ratify/plugins/referrerstore/sample/... -o ./bin/plugins/referrerstore/ ./plugins/referrerstore/sample
	go build -cover -coverpkg=github.com/ratify-project/ratify/plugins/verifier/sbom/... -o ./bin/plugins/ ./plugins/verifier/sbom
	go build -cover -coverpkg=github.com/ratify-project/ratify/plugins/verifier/schemavalidator/... -o ./bin/plugins/ ./plugins/verifier/schemavalidator
	go build -cover -coverpkg=github.com/ratify-project/ratify/plugins/verifier/vulnerabilityreport/... -o ./bin/plugins/ ./plugins/verifier/vulnerabilityreport

.PHONY: install
install:
	mkdir -p ${INSTALL_DIR}
	mkdir -p ${INSTALL_DIR}/ratify-certs/cosign
	mkdir -p ${INSTALL_DIR}/ratify-certs/notation
	cp -r ./bin/* ${INSTALL_DIR}

.PHONY: ratify-config
ratify-config:
	cp ./test/bats/tests/config/* ${INSTALL_DIR}
	cp ./test/bats/tests/certificates/wabbit-networks.io.crt ${INSTALL_DIR}/ratify-certs/notation/wabbit-networks.io.crt
	cp ./test/bats/tests/certificates/tsarootca.cer ${INSTALL_DIR}/ratify-certs/notation/tsarootca.cer
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
	kubectl apply -f ./library/multi-tenancy-validation/template.yaml
	kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml

.PHONY: delete-demo-constraints
delete-demo-constraints:
	kubectl delete -f ./library/multi-tenancy-validation/template.yaml
	kubectl delete -f ./library/multi-tenancy-validation/samples/constraint.yaml

.PHONY: deploy-rego-policy
deploy-rego-policy:
	kubectl replace -f ./config/samples/clustered/policy/config_v1beta1_policy_rego.yaml

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
	timeout 20m bats -t ${BATS_BASE_TESTS_FILE}
	EXPIRING_CERT_DIR=.staging/rotation/expiring-certs CERT_DIR=.staging/rotation GATEKEEPER_VERSION=${GATEKEEPER_VERSION} bats -t ${BATS_PLUGIN_TESTS_FILE}

.PHONY: test-e2e-cli
test-e2e-cli: e2e-dependencies e2e-create-local-registry e2e-notation-setup e2e-notation-leaf-cert-setup e2e-notation-crl-setup e2e-cosign-setup e2e-licensechecker-setup e2e-sbom-setup e2e-trivy-setup e2e-schemavalidator-setup e2e-vulnerabilityreport-setup
	rm ${GOCOVERDIR} -rf
	mkdir ${GOCOVERDIR} -p
	RATIFY_DIR=${INSTALL_DIR} TEST_REGISTRY=${TEST_REGISTRY} ${GITHUB_WORKSPACE}/bin/bats -t ${BATS_CLI_TESTS_FILE}
	go tool covdata textfmt -i=${GOCOVERDIR} -o test/e2e/coverage.txt

.PHONY: test-quick-start
test-quick-start:
	bats -t ${BATS_QUICKSTART_TESTS_FILE}

.PHONY: test-high-availability
test-high-availability:
	bats -t ${BATS_HA_TESTS_FILE}

.PHONY: generate-certs
generate-certs:
	./scripts/generate-tls-certs.sh ${CERT_DIR} ${GATEKEEPER_NAMESPACE}

generate-rotation-certs:
	mkdir -p .staging/rotation
	mkdir -p .staging/rotation/gatekeeper
	mkdir -p .staging/rotation/expiring-certs

	./scripts/generate-gk-tls-certs.sh .staging/rotation/gatekeeper ${GATEKEEPER_NAMESPACE}
	./scripts/generate-tls-certs.sh .staging/rotation ${GATEKEEPER_NAMESPACE}
	./scripts/generate-tls-certs.sh .staging/rotation/expiring-certs ${GATEKEEPER_NAMESPACE} 1

install-bats:
	# Download and install bats
	curl -sSLO https://github.com/bats-core/bats-core/archive/v${BATS_VERSION}.tar.gz && tar -zxvf v${BATS_VERSION}.tar.gz && bash bats-core-${BATS_VERSION}/install.sh ${GITHUB_WORKSPACE}

.PHONY: lint
lint:
	# Download and install golangci-lint
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	# Run golangci-lint
	golangci-lint run --print-issued-lines=false --out-format=colored-line-number --issues-exit-code=0

e2e-dependencies:
	# Download and install kind
	curl -L https://github.com/kubernetes-sigs/kind/releases/download/v${KIND_VERSION}/kind-linux-amd64 --output ${GITHUB_WORKSPACE}/bin/kind && chmod +x ${GITHUB_WORKSPACE}/bin/kind
	# Download and install kubectl
	curl -L https://dl.k8s.io/release/v${KUBERNETES_VERSION}/bin/linux/amd64/kubectl --output ${GITHUB_WORKSPACE}/bin/kubectl && chmod +x ${GITHUB_WORKSPACE}/bin/kubectl
	# Download and install bats
	curl -sSLO https://github.com/bats-core/bats-core/archive/v${BATS_VERSION}.tar.gz && tar -zxvf v${BATS_VERSION}.tar.gz && bash bats-core-${BATS_VERSION}/install.sh ${GITHUB_WORKSPACE}
	# Download and install jq
	curl -L https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 --output ${GITHUB_WORKSPACE}/bin/jq && chmod +x ${GITHUB_WORKSPACE}/bin/jq
	# Download and install yq
	curl -L https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/${YQ_BINARY} --output ${GITHUB_WORKSPACE}/bin/yq && chmod +x ${GITHUB_WORKSPACE}/bin/yq
	# Install ORAS
	curl -LO https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_amd64.tar.gz
	mkdir -p oras-install/
	tar -zxf oras*.tar.gz -C oras-install/
	mv oras-install/oras ${GITHUB_WORKSPACE}/bin
	rm -rf oras*.tar.gz oras-install/

KIND_NODE_VERSION := kindest/node:v$(KIND_KUBERNETES_VERSION)

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
		-v ${HOME}/auth/htpasswd:/etc/zot/htpasswd \
		-v ${GITHUB_WORKSPACE}/test/bats/tests/config/zot-config.json:/etc/zot/config.json \
		${LOCAL_REGISTRY_IMAGE}
	sleep 10
	${GITHUB_WORKSPACE}/bin/oras login --insecure ${TEST_REGISTRY} -u ${TEST_REGISTRY_USERNAME} -p ${TEST_REGISTRY_PASSWORD}

e2e-create-all-image:
	rm -rf .staging
	mkdir .staging
	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "all-in-one image"]' > .staging/Dockerfile
	docker buildx create --use
	docker buildx build --output type=oci,dest=.staging/all.tar -t all:v0 .staging
	${GITHUB_WORKSPACE}/bin/oras cp --from-oci-layout .staging/all.tar:v0 ${TEST_REGISTRY}/all:v0
	rm .staging/all.tar

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

e2e-helmfile-install:
	rm -rf .staging/helmfilebin
	mkdir -p .staging/helmfilebin
	curl -L https://github.com/helmfile/helmfile/releases/download/v${HELMFILE_VERSION}/helmfile_${HELMFILE_VERSION}_linux_amd64.tar.gz --output .staging/helmfilebin/helmfilebin.tar.gz
	cd .staging/helmfilebin && tar -xvf helmfilebin.tar.gz
    
e2e-docker-credential-store-setup:
	sudo apt-get install pass
	rm -rf .staging/pass
	mkdir -p .staging/pass
	cd .staging/pass && git clone https://github.com/docker/docker-credential-helpers.git
	cd .staging/pass/docker-credential-helpers && make pass
	cp .staging/pass/docker-credential-helpers/bin/build/docker-credential-pass /usr/local/bin/
	sed -i '0,/{/s/{/{\n\t"credsStore": "pass",/' ~/.docker/config.json

	gpg --batch --passphrase '' --quick-gen-key ratify default default
	pass init $$(gpg --list-keys ratify | sed -n 2p | tr -d " \t\n\r")

e2e-notation-setup:
	rm -rf .staging/notation
	mkdir -p .staging/notation
	curl -L https://github.com/notaryproject/notation/releases/download/v${NOTATION_VERSION}/notation_${NOTATION_VERSION}_linux_amd64.tar.gz --output ${GITHUB_WORKSPACE}/.staging/notation/notation.tar.gz
	tar -zxvf ${GITHUB_WORKSPACE}/.staging/notation/notation.tar.gz -C ${GITHUB_WORKSPACE}/.staging/notation

	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "notation signed image"]' > .staging/notation/Dockerfile
	docker buildx create --use
	docker buildx build --output type=oci,dest=.staging/notation/notation.tar -t notation:v0 .staging/notation
	${GITHUB_WORKSPACE}/bin/oras cp --from-oci-layout .staging/notation/notation.tar:v0 ${TEST_REGISTRY}/notation:signed
	rm .staging/notation/notation.tar

	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "notation unsigned image"]' > .staging/notation/Dockerfile
	docker buildx create --use
	docker buildx build --output type=oci,dest=.staging/notation/notation.tar -t notation:v0 .staging/notation
	${GITHUB_WORKSPACE}/bin/oras cp --from-oci-layout .staging/notation/notation.tar:v0 ${TEST_REGISTRY}/notation:unsigned
	rm .staging/notation/notation.tar

	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "notation tsa signed image"]' > .staging/notation/Dockerfile
	docker buildx create --use
	docker buildx build --output type=oci,dest=.staging/notation/notation.tar -t notation:v0 .staging/notation
	${GITHUB_WORKSPACE}/bin/oras cp --from-oci-layout .staging/notation/notation.tar:v0 ${TEST_REGISTRY}/notation:tsa
	rm .staging/notation/notation.tar
	
	rm -rf ~/.config/notation
	.staging/notation/notation cert generate-test --default "ratify-bats-test"
	NOTATION_EXPERIMENTAL=1 .staging/notation/notation sign --allow-referrers-api -u ${TEST_REGISTRY_USERNAME} -p ${TEST_REGISTRY_PASSWORD} ${TEST_REGISTRY}/notation@`${GITHUB_WORKSPACE}/bin/oras manifest fetch ${TEST_REGISTRY}/notation:signed --descriptor | jq .digest | xargs`
	NOTATION_EXPERIMENTAL=1 .staging/notation/notation sign --timestamp-url ${TIMESTAMP_URL} --timestamp-root-cert ./test/bats/tests/certificates/tsarootca.cer --allow-referrers-api -u ${TEST_REGISTRY_USERNAME} -p ${TEST_REGISTRY_PASSWORD} ${TEST_REGISTRY}/notation@`${GITHUB_WORKSPACE}/bin/oras manifest fetch ${TEST_REGISTRY}/notation:tsa --descriptor | jq .digest | xargs`
	NOTATION_EXPERIMENTAL=1 .staging/notation/notation sign --allow-referrers-api -u ${TEST_REGISTRY_USERNAME} -p ${TEST_REGISTRY_PASSWORD} ${TEST_REGISTRY}/all@`${GITHUB_WORKSPACE}/bin/oras manifest fetch ${TEST_REGISTRY}/all:v0 --descriptor | jq .digest | xargs`

e2e-notation-leaf-cert-setup:
	mkdir -p .staging/notation/leaf-test
	mkdir -p ~/.config/notation/truststore/x509/ca/leaf-test
	./scripts/generate-cert-chain.sh .staging/notation/leaf-test
	cp .staging/notation/leaf-test/leaf.crt ~/.config/notation/truststore/x509/ca/leaf-test/leaf.crt
	cp .staging/notation/leaf-test/ca.crt ~/.config/notation/truststore/x509/ca/leaf-test/root.crt
	cat .staging/notation/leaf-test/ca.crt >> .staging/notation/leaf-test/leaf.crt

	jq '.keys += [{"name":"leaf-test","keyPath":".staging/notation/leaf-test/leaf.key","certPath":".staging/notation/leaf-test/leaf.crt"}]' ~/.config/notation/signingkeys.json > tmp && mv tmp ~/.config/notation/signingkeys.json

	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "notation leaf signed image"]' > .staging/notation/Dockerfile
	docker buildx create --use
	docker buildx build --output type=oci,dest=.staging/notation/notation.tar -t notation:v0 .staging/notation
	${GITHUB_WORKSPACE}/bin/oras cp --from-oci-layout .staging/notation/notation.tar:v0 ${TEST_REGISTRY}/notation:leafSigned
	rm .staging/notation/notation.tar
	NOTATION_EXPERIMENTAL=1 .staging/notation/notation sign -u ${TEST_REGISTRY_USERNAME} -p ${TEST_REGISTRY_PASSWORD} --key "leaf-test" ${TEST_REGISTRY}/notation@`${GITHUB_WORKSPACE}/bin/oras manifest fetch ${TEST_REGISTRY}/notation:leafSigned --descriptor | jq .digest | xargs`

e2e-notation-crl-setup:
	mkdir -p .staging/notation/crl-test
	mkdir -p ~/.config/notation/truststore/x509/ca/crl-test
	./scripts/generate-crl-testing-certs.sh .staging/notation/crl-test
	cp .staging/notation/crl-test/root.crt ~/.config/notation/truststore/x509/ca/crl-test/root.crt
	cp .staging/notation/crl-test/certchain_with_crl.pem ~/.config/notation/truststore/x509/ca/crl-test/certchain_with_crl.pem

	jq '.keys += [{"name":"crl-test","keyPath":".staging/notation/crl-test/leaf.key","certPath":".staging/notation/crl-test/certchain_with_crl.pem"}]' ~/.config/notation/signingkeys.json > tmp && mv tmp ~/.config/notation/signingkeys.json

	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "notation crl signed image"]' > .staging/notation/Dockerfile
	docker buildx create --use
	docker buildx build --output type=oci,dest=.staging/notation/notation.tar -t notation:v0 .staging/notation
	${GITHUB_WORKSPACE}/bin/oras cp --from-oci-layout .staging/notation/notation.tar:v0 ${TEST_REGISTRY}/notation:crl
	rm .staging/notation/notation.tar
	NOTATION_EXPERIMENTAL=1 .staging/notation/notation sign -u ${TEST_REGISTRY_USERNAME} -p ${TEST_REGISTRY_PASSWORD} --key "crl-test" ${TEST_REGISTRY}/notation@`${GITHUB_WORKSPACE}/bin/oras manifest fetch ${TEST_REGISTRY}/notation:crl --descriptor | jq .digest | xargs`
	python3 ./scripts/crl_server.py & echo "started crl server"

e2e-cosign-setup:
	rm -rf .staging/cosign
	mkdir -p .staging/cosign
	curl -sSLO https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64
	mv cosign-linux-amd64 .staging/cosign
	chmod +x .staging/cosign/cosign-linux-amd64

	# image signed with a key
	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "cosign signed image"]' > .staging/cosign/Dockerfile
	docker buildx create --use
	docker buildx build --output type=oci,dest=.staging/cosign/cosign.tar -t cosign:v0 .staging/cosign
	${GITHUB_WORKSPACE}/bin/oras cp --from-oci-layout .staging/cosign/cosign.tar:v0 ${TEST_REGISTRY}/cosign:signed-key
	rm .staging/cosign/cosign.tar

	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "cosign unsigned image"]' > .staging/cosign/Dockerfile
	docker buildx create --use
	docker buildx build --output type=oci,dest=.staging/cosign/cosign.tar -t cosign:v0 .staging/cosign
	${GITHUB_WORKSPACE}/bin/oras cp --from-oci-layout .staging/cosign/cosign.tar:v0 ${TEST_REGISTRY}/cosign:unsigned
	rm .staging/cosign/cosign.tar

	export COSIGN_PASSWORD="test" && \
	cd .staging/cosign && \
	./cosign-linux-amd64 login ${TEST_REGISTRY} -u ${TEST_REGISTRY_USERNAME} -p ${TEST_REGISTRY_PASSWORD} && \
	./cosign-linux-amd64 generate-key-pair && \
	./cosign-linux-amd64 sign --allow-insecure-registry --allow-http-registry --tlog-upload=false --key cosign.key ${TEST_REGISTRY}/cosign@`${GITHUB_WORKSPACE}/bin/oras manifest fetch ${TEST_REGISTRY}/cosign:signed-key --descriptor | jq .digest | xargs` && \
	./cosign-linux-amd64 sign --allow-insecure-registry --allow-http-registry --tlog-upload=false --key cosign.key ${TEST_REGISTRY}/all@`${GITHUB_WORKSPACE}/bin/oras manifest fetch ${TEST_REGISTRY}/all:v0 --descriptor | jq .digest | xargs`

e2e-cosign-akv-setup:
	rm -rf .staging/cosign
	mkdir -p .staging/cosign
	curl -sSLO https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64
	mv cosign-linux-amd64 .staging/cosign
	chmod +x .staging/cosign/cosign-linux-amd64

	# image signed with a key from azure key vault
	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "cosign signed akv image"]' > .staging/cosign/Dockerfile
	docker buildx create --use
	docker buildx build --output type=oci,dest=.staging/cosign/cosign.tar -t cosign:v0 .staging/cosign
	${GITHUB_WORKSPACE}/bin/oras cp --from-oci-layout .staging/cosign/cosign.tar:v0 ${TEST_REGISTRY}/cosign:signed-key
	rm .staging/cosign/cosign.tar

	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "cosign unsigned image"]' > .staging/cosign/Dockerfile
	docker buildx create --use
	docker buildx build --output type=oci,dest=.staging/cosign/cosign.tar -t cosign:v0 .staging/cosign
	${GITHUB_WORKSPACE}/bin/oras cp --from-oci-layout .staging/cosign/cosign.tar:v0 ${TEST_REGISTRY}/cosign:unsigned
	rm .staging/cosign/cosign.tar

	export COSIGN_PASSWORD="test" && \
	cd .staging/cosign && \
	./cosign-linux-amd64 login ${TEST_REGISTRY} -u ${TEST_REGISTRY_USERNAME} -p ${TEST_REGISTRY_PASSWORD} && \
	./cosign-linux-amd64 sign --allow-insecure-registry --allow-http-registry --tlog-upload=false --key azurekms://${KEYVAULT_NAME}.vault.azure.net/${KEYVAULT_KEY_NAME} ${TEST_REGISTRY}/cosign@`${GITHUB_WORKSPACE}/bin/oras manifest fetch ${TEST_REGISTRY}/cosign:signed-key --descriptor | jq .digest | xargs` && \
	./cosign-linux-amd64 sign --allow-insecure-registry --allow-http-registry --tlog-upload=false --key azurekms://${KEYVAULT_NAME}.vault.azure.net/${KEYVAULT_KEY_NAME} ${TEST_REGISTRY}/all@`${GITHUB_WORKSPACE}/bin/oras manifest fetch ${TEST_REGISTRY}/all:v0 --descriptor | jq .digest | xargs`

e2e-licensechecker-setup:
	rm -rf .staging/licensechecker
	mkdir -p .staging/licensechecker

	# Install Syft
	curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b .staging/licensechecker ${SYFT_VERSION}

	# Build/Push Image
	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "licensechecker image"]' > .staging/licensechecker/Dockerfile
	docker buildx create --use
	docker buildx build --output type=oci,dest=.staging/licensechecker/licensechecker.tar -t licensechecker:v0 .staging/licensechecker
	${GITHUB_WORKSPACE}/bin/oras cp --from-oci-layout .staging/licensechecker/licensechecker.tar:v0 ${TEST_REGISTRY}/licensechecker:v0
	rm .staging/licensechecker/licensechecker.tar

	# Create/Attach SPDX
	.staging/licensechecker/syft -o spdx=.staging/licensechecker/sbom.spdx ${TEST_REGISTRY}/licensechecker:v0
	${GITHUB_WORKSPACE}/bin/oras attach ${TEST_REGISTRY}/licensechecker:v0 \
  		--artifact-type application/vnd.ratify.spdx.v0 \
		--distribution-spec v1.1-referrers-api \
  		.staging/licensechecker/sbom.spdx:application/text
	${GITHUB_WORKSPACE}/bin/oras attach ${TEST_REGISTRY}/all:v0 \
  		--artifact-type application/vnd.ratify.spdx.v0 \
		--distribution-spec v1.1-referrers-api \
  		.staging/licensechecker/sbom.spdx:application/text

e2e-sbom-setup:
	rm -rf .staging/sbom
	mkdir -p .staging/sbom

	# Install sbom-tool
	curl -Lo .staging/sbom/sbom-tool https://github.com/microsoft/sbom-tool/releases/download/${SBOM_TOOL_VERSION}/sbom-tool-linux-x64 && chmod +x .staging/sbom/sbom-tool
	
	# Install syft
	curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b .staging/sbom ${SYFT_VERSION}

	# Build/Push Images
	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "sbom image"]' > .staging/sbom/Dockerfile
	docker buildx create --use
	docker buildx build --output type=oci,dest=.staging/sbom/sbom.tar -t sbom:v0 .staging/sbom
	${GITHUB_WORKSPACE}/bin/oras cp --from-oci-layout .staging/sbom/sbom.tar:v0 ${TEST_REGISTRY}/sbom:v0
	rm .staging/sbom/sbom.tar
	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "sbom image unsigned"]' > .staging/sbom/Dockerfile
	docker buildx create --use
	docker buildx build --output type=oci,dest=.staging/sbom/sbom.tar -t sbom:v0 .staging/sbom
	${GITHUB_WORKSPACE}/bin/oras cp --from-oci-layout .staging/sbom/sbom.tar:v0 ${TEST_REGISTRY}/sbom:unsigned
	rm .staging/sbom/sbom.tar
	
	# Generate/Attach sbom
	# -b (BuildDropPath) - The folder to save the generated SPDX SBOM manifests to
	# -nsb (NamespaceUriBase) - The base path that will be used as the SBOM manifest's namespace. This should be a URL that's owned by your organization
	# -pn (PackageName) - The name of the package that will be used in the SBOM manifest
	# -pv (PackageVersion) - The version of the package that will be used in the SBOM manifest
	# -ps (PackageSupplier) - The supplier of the package that will be used in the SBOM manifest
	# -nsu (NamespaceUri) - The namespace that will be used as the SBOM manifest's namespace. This should be a URL that's owned by your organization
	# -di (DockerImage) - The docker image that will be used to generate the SBOM manifest
	# -m (ManifestPath) - The path to the SBOM manifest that will be generated
	# -D (Debug) - Enable debug logging
	docker pull ${TEST_REGISTRY}/sbom:v0
	.staging/sbom/sbom-tool generate -b .staging/sbom -pn ratify -di ${TEST_REGISTRY}/sbom:v0 -m .staging/sbom -pv 1.0 -ps acme -nsu ratify -nsb http://registry:5000 -D true
	${GITHUB_WORKSPACE}/bin/oras attach \
		--artifact-type application/spdx+json \
		--distribution-spec v1.1-referrers-api \
		 ${TEST_REGISTRY}/sbom:v0 \
		.staging/sbom/_manifest/spdx_2.2/manifest.spdx.json
	${GITHUB_WORKSPACE}/bin/oras attach \
		--artifact-type application/spdx+json \
		--distribution-spec v1.1-referrers-api \
		 ${TEST_REGISTRY}/sbom:unsigned \
		.staging/sbom/_manifest/spdx_2.2/manifest.spdx.json
	${GITHUB_WORKSPACE}/bin/oras attach \
		--artifact-type application/spdx+json \
		--distribution-spec v1.1-referrers-api \
		 ${TEST_REGISTRY}/all:v0 \
		.staging/sbom/_manifest/spdx_2.2/manifest.spdx.json
	sleep 5
	# Push Signature to sbom
	NOTATION_EXPERIMENTAL=1 .staging/notation/notation sign -u ${TEST_REGISTRY_USERNAME} -p ${TEST_REGISTRY_PASSWORD} ${TEST_REGISTRY}/sbom@`${GITHUB_WORKSPACE}/bin/oras discover --distribution-spec v1.1-referrers-api -o json --artifact-type application/spdx+json ${TEST_REGISTRY}/sbom:v0 | jq -r ".manifests[0].digest"`
	NOTATION_EXPERIMENTAL=1 .staging/notation/notation sign -u ${TEST_REGISTRY_USERNAME} -p ${TEST_REGISTRY_PASSWORD} ${TEST_REGISTRY}/all@`${GITHUB_WORKSPACE}/bin/oras discover --distribution-spec v1.1-referrers-api -o json --artifact-type application/spdx+json ${TEST_REGISTRY}/all:v0 | jq -r ".manifests[0].digest"` 

e2e-trivy-setup:
	rm -rf .staging/trivy
	mkdir -p .staging/trivy

	# Install Trivy
	curl -L https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz --output .staging/trivy/trivy.tar.gz
	tar -zxf .staging/trivy/trivy.tar.gz -C .staging/trivy

e2e-schemavalidator-setup:
	rm -rf .staging/schemavalidator
	mkdir -p .staging/schemavalidator

	# Build/Push Images
	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "schemavalidator image"]' > .staging/schemavalidator/Dockerfile
	docker buildx create --use
	docker buildx build --output type=oci,dest=.staging/schemavalidator/schemavalidator.tar -t schemavalidator:v0 .staging/schemavalidator
	${GITHUB_WORKSPACE}/bin/oras cp --from-oci-layout .staging/schemavalidator/schemavalidator.tar:v0 ${TEST_REGISTRY}/schemavalidator:v0
	rm .staging/schemavalidator/schemavalidator.tar

	# Create/Attach Scan Results
	.staging/trivy/trivy image --skip-db-update --format sarif --output .staging/schemavalidator/trivy-scan.sarif ${TEST_REGISTRY}/schemavalidator:v0
	${GITHUB_WORKSPACE}/bin/oras attach \
		--artifact-type application/vnd.aquasecurity.trivy.report.sarif.v1 \
		--distribution-spec v1.1-referrers-api \
		${TEST_REGISTRY}/schemavalidator:v0 \
		.staging/schemavalidator/trivy-scan.sarif:application/sarif+json
	${GITHUB_WORKSPACE}/bin/oras attach \
		--artifact-type application/vnd.aquasecurity.trivy.report.sarif.v1 \
		--distribution-spec v1.1-referrers-api \
		${TEST_REGISTRY}/all:v0 \
		.staging/schemavalidator/trivy-scan.sarif:application/sarif+json

e2e-vulnerabilityreport-setup:
	rm -rf .staging/vulnerabilityreport
	mkdir -p .staging/vulnerabilityreport

	# Build/Push Image
	printf 'FROM ${ALPINE_IMAGE_VULNERABLE}\nCMD ["echo", "vulnerabilityreport image"]' > .staging/vulnerabilityreport/Dockerfile
	docker buildx create --use
	docker buildx build --output type=oci,dest=.staging/vulnerabilityreport/vulnerabilityreport.tar -t vulnerabilityreport:v0 .staging/vulnerabilityreport
	${GITHUB_WORKSPACE}/bin/oras cp --from-oci-layout .staging/vulnerabilityreport/vulnerabilityreport.tar:v0 ${TEST_REGISTRY}/vulnerabilityreport:v0
	rm .staging/vulnerabilityreport/vulnerabilityreport.tar

	# Create/Attach Scan Result
	.staging/trivy/trivy image --skip-db-update --format sarif --output .staging/vulnerabilityreport/trivy-sarif.json ${TEST_REGISTRY}/vulnerabilityreport:v0
	${GITHUB_WORKSPACE}/bin/oras attach \
		--artifact-type application/sarif+json \
		--distribution-spec v1.1-referrers-api \
		${TEST_REGISTRY}/vulnerabilityreport:v0 \
		.staging/vulnerabilityreport/trivy-sarif.json:application/sarif+json

e2e-inlinecert-setup:
	rm -rf .staging/inlinecert
	mkdir -p .staging/inlinecert

	# build and sign an image with an alternate certificate
	printf 'FROM ${ALPINE_IMAGE}\nCMD ["echo", "alternate notation signed image"]' > .staging/inlinecert/Dockerfile
	docker buildx create --use
	docker buildx build --output type=oci,dest=.staging/inlinecert/inlinecert.tar -t inlinecert:v0 .staging/inlinecert
	${GITHUB_WORKSPACE}/bin/oras cp --from-oci-layout .staging/inlinecert/inlinecert.tar:v0 ${TEST_REGISTRY}/notation:signed-alternate
	rm .staging/inlinecert/inlinecert.tar

	.staging/notation/notation cert generate-test "alternate-cert"
	NOTATION_EXPERIMENTAL=1 .staging/notation/notation sign -u ${TEST_REGISTRY_USERNAME} -p ${TEST_REGISTRY_PASSWORD} --key "alternate-cert" ${TEST_REGISTRY}/notation@`${GITHUB_WORKSPACE}/bin/oras manifest fetch ${TEST_REGISTRY}/notation:signed-alternate --descriptor | jq .digest | xargs`

e2e-azure-setup: e2e-create-all-image e2e-notation-setup e2e-notation-leaf-cert-setup e2e-cosign-akv-setup e2e-licensechecker-setup e2e-sbom-setup e2e-trivy-setup e2e-schemavalidator-setup

e2e-deploy-gatekeeper: e2e-helm-install
	./.staging/helm/linux-amd64/helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
	./.staging/helm/linux-amd64/helm install gatekeeper/gatekeeper --version ${GATEKEEPER_VERSION} --name-template=gatekeeper --namespace ${GATEKEEPER_NAMESPACE} --create-namespace --set enableExternalData=true --set validatingWebhookTimeoutSeconds=5 --set mutatingWebhookTimeoutSeconds=2 --set auditInterval=0 --set externaldataProviderResponseCacheTTL=1s

e2e-build-crd-image:
	docker build --progress=plain --no-cache --build-arg KUBE_VERSION=${KUBERNETES_VERSION} --build-arg TARGETOS="linux" --build-arg TARGETARCH="amd64" -f crd.Dockerfile -t localbuildcrd:test ./charts/ratify/crds	

load-build-crd-image:
	kind load docker-image --name kind localbuildcrd:test

e2e-deploy-base-ratify: e2e-notation-setup e2e-notation-leaf-cert-setup e2e-cosign-setup e2e-inlinecert-setup e2e-build-crd-image load-build-crd-image e2e-build-local-ratify-base-image
	printf "{\n\t\"auths\": {\n\t\t\"registry:5000\": {\n\t\t\t\"auth\": \"`echo "${TEST_REGISTRY_USERNAME}:${TEST_REGISTRY_PASSWORD}" | tr -d '\n' | base64 -i -w 0`\"\n\t\t}\n\t}\n}" > mount_config.json

	./.staging/helm/linux-amd64/helm install ${RATIFY_NAME} \
		./charts/ratify --atomic --namespace ${GATEKEEPER_NAMESPACE} --create-namespace \
		--set image.repository=baselocalbuild \
		--set image.crdRepository=localbuildcrd \
		--set image.tag=test \
		--set gatekeeper.version=${GATEKEEPER_VERSION} \
		--set featureFlags.RATIFY_CERT_ROTATION=${CERT_ROTATION_ENABLED} \
		--set-file provider.tls.crt=${CERT_DIR}/server.crt \
		--set-file provider.tls.key=${CERT_DIR}/server.key \
		--set-file provider.tls.caCert=${CERT_DIR}/ca.crt \
		--set-file provider.tls.caKey=${CERT_DIR}/ca.key \
		--set provider.tls.cabundle="$(shell cat ${CERT_DIR}/ca.crt | base64 | tr -d '\n')" \
		--set notationCerts[0]="$$(cat ~/.config/notation/localkeys/ratify-bats-test.crt)" \
		--set cosignKeys[0]="$$(cat .staging/cosign/cosign.pub)" \
		--set cosign.key="$$(cat .staging/cosign/cosign.pub)" \
		--set oras.useHttp=true \
		--set-file dockerConfig="mount_config.json" \
		--set logger.level=debug

	rm mount_config.json

e2e-deploy-ratify: e2e-notation-setup e2e-notation-leaf-cert-setup e2e-notation-crl-setup e2e-cosign-setup e2e-cosign-setup e2e-licensechecker-setup e2e-sbom-setup e2e-trivy-setup e2e-schemavalidator-setup e2e-vulnerabilityreport-setup e2e-inlinecert-setup e2e-build-crd-image load-build-crd-image e2e-build-local-ratify-image load-local-ratify-image e2e-helm-deploy-ratify

e2e-build-local-ratify-base-image:
	docker build --progress=plain --no-cache \
		-f ./httpserver/Dockerfile \
		-t baselocalbuild:test .
	kind load docker-image --name kind baselocalbuild:test

e2e-build-local-ratify-image:
	docker build --progress=plain --no-cache \
	--build-arg build_sbom=true \
	--build-arg build_licensechecker=true \
	--build-arg build_schemavalidator=true \
	--build-arg build_vulnerabilityreport=true \
	-f ./httpserver/Dockerfile \
	-t localbuild:test .

load-local-ratify-image:
	kind load docker-image --name kind localbuild:test

e2e-helmfile-deploy-released-ratify:
	./.staging/helmfilebin/helmfile sync -f 'git::https://github.com/ratify-project/ratify.git@helmfile.yaml.gotmpl?ref=v1'

e2e-helm-deploy-ratify:
	printf "{\n\t\"auths\": {\n\t\t\"registry:5000\": {\n\t\t\t\"auth\": \"`echo "${TEST_REGISTRY_USERNAME}:${TEST_REGISTRY_PASSWORD}" | tr -d '\n' | base64 -i -w 0`\"\n\t\t}\n\t}\n}" > mount_config.json

	./.staging/helm/linux-amd64/helm install ${RATIFY_NAME} \
    ./charts/ratify --atomic --namespace ${GATEKEEPER_NAMESPACE} --create-namespace \
	--set image.repository=localbuild \
	--set image.crdRepository=localbuildcrd \
	--set image.tag=test \
	--set gatekeeper.version=${GATEKEEPER_VERSION} \
	--set featureFlags.RATIFY_CERT_ROTATION=${CERT_ROTATION_ENABLED} \
	--set-file provider.tls.crt=${CERT_DIR}/server.crt \
	--set-file provider.tls.key=${CERT_DIR}/server.key \
	--set-file provider.tls.caCert=${CERT_DIR}/ca.crt \
    --set-file provider.tls.caKey=${CERT_DIR}/ca.key \
	--set provider.tls.cabundle="$(shell cat ${CERT_DIR}/ca.crt | base64 | tr -d '\n')" \
	--set notationCerts[0]="$$(cat ~/.config/notation/localkeys/ratify-bats-test.crt)" \
	--set cosignKeys[0]="$$(cat .staging/cosign/cosign.pub)" \
	--set cosign.key="$$(cat .staging/cosign/cosign.pub)" \
	--set cosign.tLogVerify=false \
	--set oras.useHttp=true \
	--set-file dockerConfig="mount_config.json" \
	--set logger.level=debug

	rm mount_config.json

e2e-helm-deploy-ratify-without-tls-certs:
	printf "{\n\t\"auths\": {\n\t\t\"registry:5000\": {\n\t\t\t\"auth\": \"`echo "${TEST_REGISTRY_USERNAME}:${TEST_REGISTRY_PASSWORD}" | tr -d '\n' | base64 -i -w 0`\"\n\t\t}\n\t}\n}" > mount_config.json

	./.staging/helm/linux-amd64/helm install ${RATIFY_NAME} \
    ./charts/ratify --atomic --namespace ${GATEKEEPER_NAMESPACE} --create-namespace \
	--set image.repository=localbuild \
	--set image.crdRepository=localbuildcrd \
	--set image.tag=test \
	--set gatekeeper.version=${GATEKEEPER_VERSION} \
	--set featureFlags.RATIFY_CERT_ROTATION=${CERT_ROTATION_ENABLED} \
	--set notationCerts[0]="$$(cat ~/.config/notation/localkeys/ratify-bats-test.crt)" \
	--set cosign.key="$$(cat .staging/cosign/cosign.pub)" \
	--set cosignKeys[0]="$$(cat .staging/cosign/cosign.pub)" \
	--set cosign.tLogVerify=false \
	--set oras.useHttp=true \
	--set-file dockerConfig="mount_config.json" \
	--set logger.level=debug

	rm mount_config.json

e2e-helm-deploy-dapr:
	helm repo add dapr https://dapr.github.io/helm-charts/
	helm repo update
	helm upgrade --install --version ${DAPR_VERSION} dapr dapr/dapr --namespace dapr-system --create-namespace --wait

e2e-helm-deploy-redis: e2e-helm-deploy-dapr
	# overwrite pod security labels to baseline
	kubectl label --overwrite ns ${GATEKEEPER_NAMESPACE} pod-security.kubernetes.io/enforce=baseline
	kubectl label --overwrite ns ${GATEKEEPER_NAMESPACE} pod-security.kubernetes.io/warn=baseline
	
	helm repo add bitnami https://charts.bitnami.com/bitnami
	helm repo update
	helm upgrade --install redis bitnami/redis --namespace ${GATEKEEPER_NAMESPACE} --set image.tag=${REDIS_IMAGE_TAG} --wait --set replica.replicaCount=1 --set tls.enabled=true --set tls.autoGenerated=true --set tls.authClients=false
	SIGN_KEY=$(shell openssl rand 16 | hexdump -v -e '/1 "%02x"' | base64) ${GITHUB_WORKSPACE}/bin/yq -i '.data.signingKey = strenv(SIGN_KEY)' test/testdata/dapr/dapr-redis-secret.yaml
	kubectl apply -f test/testdata/dapr/dapr-redis-secret.yaml -n ${GATEKEEPER_NAMESPACE}
	kubectl apply -f test/testdata/dapr/dapr-redis.yaml -n ${GATEKEEPER_NAMESPACE}
 
e2e-helm-deploy-ratify-replica: e2e-helm-deploy-redis e2e-notation-setup e2e-build-crd-image load-build-crd-image e2e-build-local-ratify-image load-local-ratify-image
	printf "{\n\t\"auths\": {\n\t\t\"registry:5000\": {\n\t\t\t\"auth\": \"`echo "${TEST_REGISTRY_USERNAME}:${TEST_REGISTRY_PASSWORD}" | tr -d '\n' | base64 -i -w 0`\"\n\t\t}\n\t}\n}" > mount_config.json

	./.staging/helm/linux-amd64/helm install ${RATIFY_NAME} \
    ./charts/ratify --atomic --namespace ${GATEKEEPER_NAMESPACE} --create-namespace \
	--set image.repository=localbuild \
	--set image.crdRepository=localbuildcrd \
	--set image.tag=test \
	--set gatekeeper.version=${GATEKEEPER_VERSION} \
	--set featureFlags.RATIFY_CERT_ROTATION=${CERT_ROTATION_ENABLED} \
	--set-file provider.tls.crt=${CERT_DIR}/server.crt \
	--set-file provider.tls.key=${CERT_DIR}/server.key \
	--set-file provider.tls.caCert=${CERT_DIR}/ca.crt \
    --set-file provider.tls.caKey=${CERT_DIR}/ca.key \
	--set provider.tls.cabundle="$(shell cat ${CERT_DIR}/ca.crt | base64 | tr -d '\n')" \
	--set notationCerts[0]="$$(cat ~/.config/notation/localkeys/ratify-bats-test.crt)" \
	--set oras.useHttp=true \
	--set cosign.enabled=false \
	--set-file dockerConfig="mount_config.json" \
	--set logger.level=debug \
	--set replicaCount=2 \
	--set provider.cache.type="dapr" \
	--set provider.cache.name="dapr-redis" \
	--set featureFlags.RATIFY_EXPERIMENTAL_HIGH_AVAILABILITY=true \
	--set resources.requests.memory="64Mi" \
	--set resources.requests.cpu="200m"

	rm mount_config.json

e2e-aks:
	./scripts/azure-ci-test.sh ${KUBERNETES_VERSION} ${GATEKEEPER_VERSION} ${TENANT_ID} ${GATEKEEPER_NAMESPACE} ${CERT_DIR} ${AZURE_SP_OBJECT_ID}

e2e-cleanup:
	./scripts/azure-ci-test-cleanup.sh ${AZURE_SUBSCRIPTION_ID}
##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen conversion-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations. Also generate conversions between structs of different API versions.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."
	$(CONVERSION_GEN) \
        --go-header-file "./hack/boilerplate.go.txt" \
        --output-file "zz_generated.conversion.go" \
		./api/v1beta1 ./api/v1alpha1


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
CONTROLLER_TOOLS_VERSION ?= v0.15.0
CONVERSION_TOOLS_VERSION ?= v0.30.2

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
