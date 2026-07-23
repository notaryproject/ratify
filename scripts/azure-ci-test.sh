#!/usr/bin/env bash
##--------------------------------------------------------------------
#
# Copyright The Ratify Authors.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
##--------------------------------------------------------------------
#
# AKS end-to-end test for the Ratify gatekeeper provider.
#
##--------------------------------------------------------------------

set -o errexit
set -o nounset
set -o pipefail

SUFFIX=$(openssl rand -hex 2)
export GROUP_NAME="${GROUP_NAME:-ratify-e2e-${SUFFIX}}"
export ACR_NAME="${ACR_NAME:-ratifyacr${SUFFIX}}"
export AKS_NAME="${AKS_NAME:-ratify-aks-${SUFFIX}}"
export KEYVAULT_NAME="${KEYVAULT_NAME:-ratify-akv-${SUFFIX}}"
export USER_ASSIGNED_IDENTITY_NAME="${USER_ASSIGNED_IDENTITY_NAME:-ratify-e2e-identity-${SUFFIX}}"
export LOCATION="${LOCATION:-westus2}"
export KUBERNETES_VERSION=${1:-1.30.6}
GATEKEEPER_VERSION=${2:-3.18.0}
TENANT_ID=$3
export RATIFY_NAMESPACE=${4:-gatekeeper-system}
CERT_DIR=${5:-"${HOME}/ratify/certs"}
export AZURE_SP_OBJECT_ID=$6
export NOTATION_PEM_NAME="notation"
# The variables below are only needed by capabilities that are not yet
# wired into the v2 AKS e2e. They are kept commented (rather than deleted)
# so the pieces are easy to re-enable in the follow-up PRs that add them and
# so the diff against the v1 script stays traceable.
# TODO(follow-up: notation leaf-cert chain):
# export NOTATION_CHAIN_PEM_NAME="notationchain"
# TODO(follow-up: cosign on AKV):
# export KEYVAULT_KEY_NAME="test-key"

TAG="test${SUFFIX}"
REGISTRY="${ACR_NAME}.azurecr.io"

# Helm release name for the v2 gatekeeper provider chart. It is used as the
# fully-qualified name, and therefore also as the in-cluster service DNS name
# that the TLS certificate SAN must match.
RATIFY_RELEASE_NAME="ratify-gatekeeper-provider"
# Service account name must match the federated identity credential subject
# created in scripts/create-azure-resources.sh
# (system:serviceaccount:${RATIFY_NAMESPACE}:ratify-admin).
SERVICE_ACCOUNT_NAME="ratify-admin"

build_push_to_acr() {
  echo "Building and pushing the ratify-gatekeeper-provider image to ACR"
  docker build --progress=plain --no-cache \
    -f ./Dockerfile \
    -t "${REGISTRY}/test/ratify-gatekeeper-provider:${TAG}" .
  docker push "${REGISTRY}/test/ratify-gatekeeper-provider:${TAG}"
}

upload_cert_to_akv() {
  rm -f notation.pem
  cat ~/.config/notation/localkeys/ratify-bats-test.key >>notation.pem
  cat ~/.config/notation/localkeys/ratify-bats-test.crt >>notation.pem

  echo "uploading notation.pem"
  az keyvault certificate import \
    --vault-name ${KEYVAULT_NAME} \
    -n ${NOTATION_PEM_NAME} \
    -f notation.pem

  # The leaf-cert test configures the generated certs as inline trust stores,
  # so the leaf signing chain does not need to be uploaded to AKV.
  # rm -f notationchain.pem
  # cat .staging/notation/leaf-test/leaf.key >>notationchain.pem
  # cat .staging/notation/leaf-test/leaf.crt >>notationchain.pem
  # echo "uploading notationchain.pem"
  # az keyvault certificate import \
  #   --vault-name ${KEYVAULT_NAME} \
  #   -n ${NOTATION_CHAIN_PEM_NAME} \
  #   -f notationchain.pem \
  #   -p @./test/bats/tests/config/akvpolicy.json
}

# TODO(follow-up: cosign on AKV): create the AKV signing key used by the
# cosign verifier. cosign-on-AKV is not yet wired into the v2 AKS e2e;
# re-enable this together with the "cosign test" bats case and the
# create_key_akv call in main().
# create_key_akv() {
#   az keyvault key create \
#     --vault-name ${KEYVAULT_NAME} \
#     -n ${KEYVAULT_KEY_NAME} \
#     --kty RSA \
#     --size 2048
# }

deploy_gatekeeper() {
  echo "deploying gatekeeper"
  make e2e-deploy-gatekeeper GATEKEEPER_VERSION=${GATEKEEPER_VERSION} GATEKEEPER_NAMESPACE="gatekeeper-system"
}

deploy_ratify() {
  echo "deploying the ratify-gatekeeper-provider (v2)"
  local IDENTITY_CLIENT_ID=$(az identity show --name ${USER_ASSIGNED_IDENTITY_NAME} --resource-group ${GROUP_NAME} --query 'clientId' -o tsv)
  local VAULT_URI=$(az keyvault show --name ${KEYVAULT_NAME} --resource-group ${GROUP_NAME} --query "properties.vaultUri" -otsv)

  # Generate static TLS certificates whose SAN matches the provider service DNS
  # (${RATIFY_RELEASE_NAME}.${RATIFY_NAMESPACE}).
  ./scripts/generate-tls-certs.sh ${CERT_DIR} ${RATIFY_RELEASE_NAME} ${RATIFY_NAMESPACE}

  helm install ${RATIFY_RELEASE_NAME} \
    ./deployments/ratify-gatekeeper-provider --atomic \
    --namespace ${RATIFY_NAMESPACE} --create-namespace \
    --set image.repository=${REGISTRY}/test/ratify-gatekeeper-provider \
    --set image.tag=${TAG} \
    --set-file provider.tls.crt=${CERT_DIR}/server.crt \
    --set-file provider.tls.key=${CERT_DIR}/server.key \
    --set-file provider.tls.caCert=${CERT_DIR}/ca.crt \
    --set provider.tls.disableCertRotation=true \
    --set executor.scopes[0]=${REGISTRY}/notation \
    --set stores[0].credential.provider=azure \
    --set notation.scopes[0]=${REGISTRY}/notation \
    --set notation.certs[0].provider=azurekeyvault \
    --set notation.certs[0].vaultURL=${VAULT_URI} \
    --set notation.certs[0].clientID=${IDENTITY_CLIENT_ID} \
    --set notation.certs[0].tenantID=${TENANT_ID} \
    --set notation.certs[0].certificates[0].name=${NOTATION_PEM_NAME} \
    --set serviceAccount.name=${SERVICE_ACCOUNT_NAME} \
    --set-string serviceAccount.annotations."azure\.workload\.identity/client-id"=${IDENTITY_CLIENT_ID}
}

save_logs() {
  echo "Saving logs"
  local LOG_SUFFIX="${KUBERNETES_VERSION}-${GATEKEEPER_VERSION}"
  kubectl logs -n gatekeeper-system -l control-plane=controller-manager --tail=-1 >logs-externaldata-controller-aks-${LOG_SUFFIX}.json || true
  kubectl logs -n gatekeeper-system -l control-plane=audit-controller --tail=-1 >logs-externaldata-audit-aks-${LOG_SUFFIX}.json || true
  kubectl logs -n ${RATIFY_NAMESPACE} -l app.kubernetes.io/name=ratify-gatekeeper-provider --tail=-1 >logs-ratify-gatekeeper-provider-aks-${LOG_SUFFIX}.json || true
}

cleanup() {
  save_logs || true

  echo "Delete key vault"
  az keyvault delete --name "${KEYVAULT_NAME}" --resource-group "${GROUP_NAME}" || true

  echo "Purge key vault"
  az keyvault purge --name "${KEYVAULT_NAME}" --no-wait || true

  echo "Deleting child resources (RG is shared, do not delete)"
  az aks      delete -g "${GROUP_NAME}" -n "${AKS_NAME}"                     --yes --no-wait || true
  az acr      delete -g "${GROUP_NAME}" -n "${ACR_NAME}"                     --yes           || true
  az identity delete -g "${GROUP_NAME}" -n "${USER_ASSIGNED_IDENTITY_NAME}"                  || true
}

trap cleanup EXIT

main() {
  ./scripts/create-azure-resources.sh
  # TODO(follow-up: cosign on AKV): create the AKV signing key for cosign.
  # create_key_akv

  local ACR_USER_NAME="00000000-0000-0000-0000-000000000000"
  local ACR_PASSWORD=$(az acr login --name ${ACR_NAME} --expose-token --output tsv --query accessToken)

  # Build and push the notation signed/unsigned test images to ACR and sign
  # the signed image with the ratify-bats-test certificate. This replaces the
  # v1 `make e2e-azure-setup` (which also provisioned the cosign key and KMP
  # inputs); the full setup returns once those verifiers land in v2.
  make e2e-create-all-image e2e-notation-setup \
    TEST_REGISTRY=$REGISTRY \
    TEST_REGISTRY_USERNAME=${ACR_USER_NAME} \
    TEST_REGISTRY_PASSWORD=${ACR_PASSWORD}

  build_push_to_acr
  upload_cert_to_akv
  deploy_gatekeeper
  deploy_ratify

  # Consumed by test cases that configure AKV-backed verifiers through the
  # bats env; re-enable together with those cases in the follow-up PRs.
  # local IDENTITY_CLIENT_ID=$(az identity show --name ${USER_ASSIGNED_IDENTITY_NAME} --resource-group ${GROUP_NAME} --query 'clientId' -o tsv)
  # local VAULT_URI=$(az keyvault show --name ${KEYVAULT_NAME} --resource-group ${GROUP_NAME} --query "properties.vaultUri" -otsv)
  TEST_REGISTRY=$REGISTRY bats -t ./test/bats/azure-test.bats
}

main
