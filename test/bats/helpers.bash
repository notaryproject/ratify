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

#!/bin/bash

assert_success() {
  if [[ "$status" != 0 ]]; then
    echo "expected: 0"
    echo "actual: $status"
    echo "output: $output"
    return 1
  fi
}

assert_failure() {
  if [[ "$status" == 0 ]]; then
    echo "expected: non-zero exit code"
    echo "actual: $status"
    echo "output: $output"
    return 1
  fi
}

assert_cmd_verify_success() {
  if [[ "$status" != 0 ]]; then
    return 1
  fi
  if [[ "$output" == *'"isSuccess": false,'* ]]; then
    echo $output
    return 1
  fi
}

assert_cmd_multi_verifier_success() {
  if [[ "$status" != 0 ]]; then
    return 1
  fi
  if [[ "$output" == *'{ "isSuccess": true, "verifierReports"'* ]]; then
    echo $output
    return 1
  fi
}

assert_cmd_verify_success_with_type() {
  if [[ "$status" != 0 ]]; then
    return 1
  fi
  if [[ "$output" == *'"isSuccess": false,'* ]]; then
    echo $output
    return 1
  fi
  if [[ "$output" != *'"type":'* ]]; then
    echo $output
    return 1
  fi
}

assert_cmd_cosign_keyless_verify_bundle_success() {
  if [[ "$status" != 0 ]]; then
    return 1
  fi
  if [[ "$output" == *'"bundleVerified": false,'* ]]; then
    echo $output
    return 1
  fi
}

assert_cmd_verify_failure() {
  if [[ "$status" != 0 ]]; then
    return 1
  fi
  if [[ "$output" == *'"isSuccess": true,'* ]]; then
    echo $output
    return 1
  fi
}

assert_mutate_success() {
  if [[ "$status" != 0 ]]; then
    echo $result
    return 1
  fi
  if [[ "$output" == "" ]]; then
    echo "expected digest to be present in image"
    return 1
  fi
}

wait_for_process() {
  wait_time="$1"
  sleep_time="$2"
  cmd="$3"
  while [ "$wait_time" -gt 0 ]; do
    if eval "$cmd"; then
      return 0
    else
      sleep "$sleep_time"
      echo "# retrying $cmd" >&3
      wait_time=$((wait_time - sleep_time))
    fi
  done
  return 1
}

revoke_crl() {
  URL_LEAF="http://localhost:10086/leaf/revoke"
  curl -s -X POST "$URL_LEAF" -H "Content-Type: application/json"
  URL_INTER=http://localhost:10086/intermediate/unrevoke
  curl -s -X POST "$URL_INTER" -H "Content-Type: application/json"
}

unrevoke_crl() {
  URL_LEAF="http://localhost:10086/leaf/unrevoke"
  curl -s -X POST "$URL_LEAF" -H "Content-Type: application/json"
  URL_INTER=http://localhost:10086/intermediate/unrevoke
  curl -s -X POST "$URL_INTER" -H "Content-Type: application/json"
}

delete_crl_cache() {
  rm -rf $HOME/.cache/notation/crl
}

check_crl_cache_deleted() {
  if [[ -d "$HOME/.cache/notation/crl" ]]; then
    echo "The directory exists."
    return 1
  fi
}

check_crl_cache_created() {
  if [[ ! -d "$HOME/.cache/notation/crl" ]]; then
    echo "The directory does not exist."
    return 1
  fi
}

# restore_executor applies a saved executor YAML back to the cluster.
# Uses server-side apply with force-conflicts to avoid resourceVersion staleness.
restore_executor() {
  local file="$1"
  local ns="${2:-gatekeeper-system}"
  if [[ ! -f "$file" ]]; then
    echo "restore_executor: file $file not found"
    return 1
  fi
  cat "$file" | sed '/^\s*resourceVersion:/d; /^\s*uid:/d; /^\s*creationTimestamp:/d; /^\s*generation:/d' | \
    kubectl apply --server-side --force-conflicts -f -
}

# executor_reconcile_count echoes how many times the controller has logged a
# reconcile of the cluster-scoped Executor. Tests need this because
# status.succeeded stays true from the previous reconciliation and is not reset
# when a new spec is applied, so it cannot be used on its own to tell that the
# newly applied spec has been processed.
# usage: executor_reconcile_count [namespace]
executor_reconcile_count() {
  local ns="${1:-gatekeeper-system}"
  local deploy
  deploy="$(kubectl get deploy -n "$ns" -l app.kubernetes.io/name=ratify-gatekeeper-provider -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
  if [[ -z "$deploy" ]]; then
    echo 0
    return 0
  fi
  kubectl logs "deployment/${deploy}" -n "$ns" --tail=-1 2>/dev/null | grep "Reconciling Executor" | wc -l
}

# wait_for_executor_reconcile blocks until the controller has logged at least one
# reconcile beyond <baseline> and the Executor reports success. Capture
# <baseline> with executor_reconcile_count before applying the new spec.
# usage: wait_for_executor_reconcile <executor-name> <baseline> [namespace] [timeout-seconds]
wait_for_executor_reconcile() {
  local executor="$1"
  local baseline="$2"
  local ns="${3:-gatekeeper-system}"
  local timeout="${4:-120}"
  local waited=0
  local count
  while [[ "$waited" -lt "$timeout" ]]; do
    count="$(executor_reconcile_count "$ns")"
    if [[ "$count" -gt "$baseline" ]] &&
      [[ "$(kubectl get executors.config.ratify.sh/"$executor" -o jsonpath='{.status.succeeded}')" == "true" ]]; then
      return 0
    fi
    sleep 2
    waited=$((waited + 2))
  done
  echo "timed out waiting for executor ${executor} to reconcile: baseline=${baseline} current=$(executor_reconcile_count "$ns")"
  kubectl get executors.config.ratify.sh/"$executor" -o jsonpath='{.status}'
  return 1
}

# trigger_executor_reconcile forces the controller to re-reconcile a
# cluster-scoped Executor -- and therefore to rebuild its plugins and re-fetch
# any externally sourced trust material -- by stamping a unique annotation on it.
# usage: trigger_executor_reconcile <executor-name>
trigger_executor_reconcile() {
  local executor="$1"
  kubectl annotate executors.config.ratify.sh/"$executor" \
    ratify.sh/e2e-reconcile-token="$(date +%s%N)" --overwrite
}

# set_executor_akv_certificate points the notation-1 verifier of a cluster-scoped
# Executor at a specific Azure Key Vault certificate, optionally pinning a
# version, and applies the result. An empty version means "latest".
# usage: set_executor_akv_certificate <executor-name> <cert-name> [cert-version]
set_executor_akv_certificate() {
  local executor="$1"
  local cert_name="$2"
  local cert_version="${3:-}"
  kubectl get executors.config.ratify.sh/"$executor" -o json |
    jq --arg name "$cert_name" --arg version "$cert_version" '
      del(.metadata.managedFields, .metadata.resourceVersion, .metadata.uid, .metadata.creationTimestamp, .metadata.generation, .status)
      | .spec.verifiers |= map(
          if .name == "notation-1"
          then .parameters.certificates[0].azurekeyvault.certificates = [{name: $name, version: $version}]
          else . end)' |
    kubectl apply --server-side --force-conflicts -f -
}

uninstall_ratify_release() {
  local helm="$1"
  "$helm" uninstall ratify-gatekeeper-provider --namespace gatekeeper-system 2>/dev/null || true
  kubectl delete executors.config.ratify.sh/ratify-gatekeeper-provider-executor-1 --ignore-not-found=true 2>/dev/null || true
  kubectl delete providers.externaldata.gatekeeper.sh ratify-gatekeeper-provider ratify-gatekeeper-mutation-provider --ignore-not-found=true 2>/dev/null || true
  kubectl delete secret ratify-gatekeeper-provider-tls -n gatekeeper-system --ignore-not-found=true 2>/dev/null || true
}
