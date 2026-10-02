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
  if [[ "$output" == *'"succeeded": false'* ]]; then
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
  if [[ "$output" == *'"succeeded": true'* ]]; then
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

# apply_namespaced_notation_executor renders and applies a NamespacedExecutor
# whose notation verifier trusts a single inline CA certificate. It lets a test
# give each tenant namespace its own trust material.
# usage: apply_namespaced_notation_executor <namespace> <name> <ca-cert-path>
apply_namespaced_notation_executor() {
  local ns="$1"
  local name="$2"
  local cert_path="$3"
  local cert
  if [[ ! -f "$cert_path" ]]; then
    echo "apply_namespaced_notation_executor: certificate $cert_path not found"
    return 1
  fi
  cert="$(cat "$cert_path")"
  jq -n --arg ns "$ns" --arg name "$name" --arg cert "$cert" '{
    apiVersion: "config.ratify.sh/v2beta1",
    kind: "NamespacedExecutor",
    metadata: {name: $name, namespace: $ns},
    spec: {
      scopes: ["registry:5000"],
      concurrency: 3,
      stores: [{type: "registry-store", parameters: {plainHttp: true, credential: {provider: "static", username: "test_user", password: "test_pw"}}}],
      verifiers: [{name: "notation", type: "notation", parameters: {certificates: [{type: "ca", inline: {certs: $cert}}]}}],
      policyEnforcer: {type: "threshold-policy", parameters: {policy: {threshold: 1, rules: [{verifierName: "notation"}]}}}
    }
  }' | kubectl apply -f -
}

# executor_reconcile_count echoes how many reconciles the controller has logged
# for the cluster-scoped Executor. status.succeeded is not reset when a new spec
# is applied, so it cannot be used on its own to detect a completed reconcile.
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

# wait_for_executor_reconcile blocks until the controller has logged a reconcile
# beyond <baseline> and the Executor reports success.
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

uninstall_ratify_release() {
  local helm="$1"
  "$helm" uninstall ratify-gatekeeper-provider --namespace gatekeeper-system 2>/dev/null || true
  kubectl delete executors.config.ratify.sh/ratify-gatekeeper-provider-executor-1 --ignore-not-found=true 2>/dev/null || true
  kubectl delete providers.externaldata.gatekeeper.sh ratify-gatekeeper-provider ratify-gatekeeper-mutation-provider --ignore-not-found=true 2>/dev/null || true
  kubectl delete secret ratify-gatekeeper-provider-tls -n gatekeeper-system --ignore-not-found=true 2>/dev/null || true
}
