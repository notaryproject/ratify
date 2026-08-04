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
# Provision the Azure resources for the AKS identity binding e2e test.
#
# Unlike the workload-identity e2e (scripts/create-azure-resources.sh) this
# script does NOT create a per-cluster federated identity credential. Instead it
# creates an AKS identity binding (preview) that maps the user-assigned managed
# identity to the cluster using a single, AKS-managed federated credential, and
# authorizes the ratify service account to use that identity through Kubernetes
# RBAC. See https://learn.microsoft.com/azure/aks/identity-bindings-concepts.
#
##--------------------------------------------------------------------

set -o errexit
set -o nounset
set -o pipefail

: "${AKS_NAME:?AKS_NAME environment variable empty or not defined.}"
: "${ACR_NAME:?ACR_NAME environment variable empty or not defined.}"

# Minimum tooling versions required for identity bindings (preview).
readonly MIN_AKS_PREVIEW_VERSION="18.0.0b26"

ensure_preview_tooling() {
  # The aks-preview extension provides the "az aks identity-binding" command
  # group. Install it if missing; the caller is responsible for a version that
  # is at least ${MIN_AKS_PREVIEW_VERSION}.
  if ! az extension show --name aks-preview >/dev/null 2>&1; then
    echo "Installing aks-preview extension"
    az extension add --name aks-preview
  fi

  echo "Registering the IdentityBindingPreview feature flag (idempotent)"
  az feature register --namespace Microsoft.ContainerService --name IdentityBindingPreview >/dev/null || true

  # Wait for the feature to reach the Registered state.
  local state=""
  for _ in $(seq 1 30); do
    state="$(az feature show --namespace Microsoft.ContainerService --name IdentityBindingPreview --query properties.state -o tsv 2>/dev/null || echo)"
    if [ "${state}" = "Registered" ]; then
      break
    fi
    echo "Waiting for IdentityBindingPreview to register (current: ${state:-unknown})..."
    sleep 20
  done
  az provider register --namespace Microsoft.ContainerService >/dev/null || true
}

create_user_managed_identity() {
  SUBSCRIPTION_ID="$(az account show --query id --output tsv)"

  az identity create \
    --name "${USER_ASSIGNED_IDENTITY_NAME}" \
    --resource-group "${GROUP_NAME}" \
    --location "${LOCATION}" \
    --subscription "${SUBSCRIPTION_ID}"

  USER_ASSIGNED_IDENTITY_OBJECT_ID="$(az identity show --name "${USER_ASSIGNED_IDENTITY_NAME}" --resource-group "${GROUP_NAME}" --query 'principalId' -otsv)"
  USER_ASSIGNED_IDENTITY_RESOURCE_ID="$(az identity show --name "${USER_ASSIGNED_IDENTITY_NAME}" --resource-group "${GROUP_NAME}" --query 'id' -otsv)"
  USER_ASSIGNED_IDENTITY_CLIENT_ID="$(az identity show --name "${USER_ASSIGNED_IDENTITY_NAME}" --resource-group "${GROUP_NAME}" --query 'clientId' -otsv)"
  USER_ASSIGNED_IDENTITY_TENANT_ID="$(az identity show --name "${USER_ASSIGNED_IDENTITY_NAME}" --resource-group "${GROUP_NAME}" --query 'tenantId' -otsv)"
}

create_acr() {
  az acr create --name "${ACR_NAME}" \
    --resource-group "${GROUP_NAME}" \
    --sku Standard >/dev/null
  az acr login -n "${ACR_NAME}"
  echo "ACR '${ACR_NAME}' is created"

  # Grant the managed identity acrpull on the registry so identity binding based
  # authentication can pull manifests and signatures.
  az role assignment create \
    --assignee-object-id "${USER_ASSIGNED_IDENTITY_OBJECT_ID}" \
    --assignee-principal-type "ServicePrincipal" \
    --role acrpull \
    --scope "subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${GROUP_NAME}/providers/Microsoft.ContainerRegistry/registries/${ACR_NAME}"
}

create_aks() {
  # Workload identity and the OIDC issuer are prerequisites for identity
  # bindings. --attach-acr grants the cluster kubelet identity acrpull so it can
  # pull the ratify provider image and admitted workload images; this is the
  # standard kubelet image-pull path and is independent of the identity binding
  # based authentication that ratify itself performs during verification.
  az aks create \
    --resource-group "${GROUP_NAME}" \
    --name "${AKS_NAME}" \
    --node-vm-size Standard_DS3_v2 \
    --kubernetes-version "${KUBERNETES_VERSION}" \
    --node-count 1 \
    --no-ssh-key \
    --enable-workload-identity \
    --enable-oidc-issuer \
    --attach-acr "${ACR_NAME}" >/dev/null
  echo "AKS '${AKS_NAME}' is created"

  az aks get-credentials --resource-group "${GROUP_NAME}" --name "${AKS_NAME}" --overwrite-existing
  echo "Connected to AKS cluster"

  # Confirm the identity binding (preview) workload identity webhook is present.
  if ! kubectl -n kube-system get pods -l azure-workload-identity.io/system=true -o yaml | grep -q "v1.6.0"; then
    echo "WARNING: expected the identity binding preview workload identity webhook (v1.6.0+)."
  fi
}

create_identity_binding() {
  # Map the managed identity to this cluster with an identity binding. AKS
  # creates (or reuses) a single federated identity credential per identity.
  az aks identity-binding create \
    --resource-group "${GROUP_NAME}" \
    --cluster-name "${AKS_NAME}" \
    --name "${USER_ASSIGNED_IDENTITY_NAME}-ib" \
    --managed-identity-resource-id "${USER_ASSIGNED_IDENTITY_RESOURCE_ID}"

  # Authorize the ratify service account to use the managed identity through
  # Kubernetes RBAC. The cluster admission webhook checks this permission before
  # projecting an identity binding token into the pod.
  kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: use-mi-${USER_ASSIGNED_IDENTITY_CLIENT_ID}
rules:
  - verbs: ["use-managed-identity"]
    apiGroups: ["cid.wi.aks.azure.com"]
    resources: ["${USER_ASSIGNED_IDENTITY_CLIENT_ID}"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: use-mi-${USER_ASSIGNED_IDENTITY_CLIENT_ID}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: use-mi-${USER_ASSIGNED_IDENTITY_CLIENT_ID}
subjects:
  - kind: ServiceAccount
    name: ${SERVICE_ACCOUNT_NAME}
    namespace: ${RATIFY_NAMESPACE}
EOF
}

main() {
  echo "Using resource group ${GROUP_NAME} in ${LOCATION}"

  ensure_preview_tooling
  create_user_managed_identity
  create_acr
  create_aks
  create_identity_binding
}

main
