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

set -o errexit
set -o nounset
set -o pipefail

: "${AKS_NAME:?AKS_NAME environment variable empty or not defined.}"
: "${ACR_NAME:?ACR_NAME environment variable empty or not defined.}"

create_user_managed_identity() {
  SUBSCRIPTION_ID="$(az account show --query id --output tsv)"

  az identity create \
    --name "${USER_ASSIGNED_IDENTITY_NAME}" \
    --resource-group "${GROUP_NAME}" \
    --location "${LOCATION}" \
    --subscription "${SUBSCRIPTION_ID}"

  USER_ASSIGNED_IDENTITY_OBJECT_ID="$(az identity show --name "${USER_ASSIGNED_IDENTITY_NAME}" --resource-group "${GROUP_NAME}" --query 'principalId' -otsv)"
}

create_acr() {
  az acr create --name "${ACR_NAME}" \
    --resource-group "${GROUP_NAME}" \
    --sku Standard >/dev/null
  az acr login -n ${ACR_NAME}
  echo "ACR '${ACR_NAME}' is created"

  # Enable acrpull role to the user-managed identity.
  az role assignment create \
    --assignee-object-id ${USER_ASSIGNED_IDENTITY_OBJECT_ID} \
    --assignee-principal-type "ServicePrincipal" \
    --role acrpull \
    --scope subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${GROUP_NAME}/providers/Microsoft.ContainerRegistry/registries/${ACR_NAME}
}

create_aks() {
  az aks create \
    --resource-group "${GROUP_NAME}" \
    --name "${AKS_NAME}" \
    --node-vm-size Standard_DS3_v2 \
    --kubernetes-version "${KUBERNETES_VERSION}" \
    --node-count 1 \
    --generate-ssh-keys \
    --enable-workload-identity \
    --attach-acr ${ACR_NAME} \
    --enable-oidc-issuer >/dev/null
  echo "AKS '${AKS_NAME}' is created"

  az aks get-credentials --resource-group ${GROUP_NAME} --name ${AKS_NAME}
  echo "Connected to AKS cluster"

  # Establish federated identity credential between the managed identity, the
  # service account issuer and the subject.
  local AKS_OIDC_ISSUER="$(az aks show -n ${AKS_NAME} -g ${GROUP_NAME} --query "oidcIssuerProfile.issuerUrl" -otsv)"
  az identity federated-credential create \
    --name ratify-federated-credential \
    --identity-name "${USER_ASSIGNED_IDENTITY_NAME}" \
    --resource-group "${GROUP_NAME}" \
    --issuer "${AKS_OIDC_ISSUER}" \
    --subject system:serviceaccount:"${RATIFY_NAMESPACE}":"ratify-admin"

  # It takes a while for the federated identity credentials to be propagated
  # after being initially added.
  sleep 1m
}

create_akv() {
  az keyvault create \
    --resource-group ${GROUP_NAME} \
    --location "${LOCATION}" \
    --name ${KEYVAULT_NAME}

  echo "AKV '${KEYVAULT_NAME}' is created"

  # Grant ratify identity permissions to access the secret
  az role assignment create \
    --assignee-object-id ${USER_ASSIGNED_IDENTITY_OBJECT_ID} \
    --assignee-principal-type "ServicePrincipal" \
    --role "Key Vault Secrets User" \
    --scope subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${GROUP_NAME}/providers/Microsoft.KeyVault/vaults/${KEYVAULT_NAME}
  
  # Grant ratify identity permissions to access keys
  az role assignment create \
    --assignee-object-id ${USER_ASSIGNED_IDENTITY_OBJECT_ID} \
    --assignee-principal-type "ServicePrincipal" \
    --role "Key Vault Crypto User" \
    --scope subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${GROUP_NAME}/providers/Microsoft.KeyVault/vaults/${KEYVAULT_NAME}

  # Grant runner SP permissions to create keys and import certificates
  az role assignment create \
    --assignee-object-id ${AZURE_SP_OBJECT_ID} \
    --assignee-principal-type "${AZURE_SP_PRINCIPAL_TYPE:-ServicePrincipal}" \
    --role "Key Vault Administrator" \
    --scope subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${GROUP_NAME}/providers/Microsoft.KeyVault/vaults/${KEYVAULT_NAME}
}

main() {
  az group create --name "${GROUP_NAME}" --tags "ratifye2e" --location "${LOCATION}" >/dev/null

  create_user_managed_identity
  create_akv
  create_acr
  create_aks
}

main
