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
  # Strip stale metadata fields, then server-side apply with force
  cat "$file" | sed '/^\s*resourceVersion:/d; /^\s*uid:/d; /^\s*creationTimestamp:/d; /^\s*generation:/d' | \
    kubectl apply --server-side --force-conflicts -f -
}

# get_notation_cert extracts the inline notation certificate from the currently
# deployed executor. Returns the PEM cert as stored in the executor spec.
get_notation_cert() {
  local executor_name="${1:-ratify-ratify-gatekeeper-provider-executor-1}"
  kubectl get executors.config.ratify.dev/${executor_name} -o jsonpath='{.spec.verifiers[?(@.name=="notation-1")].parameters.certificates[0].inline}' 2>/dev/null || \
  kubectl get executors.config.ratify.dev/${executor_name} -o jsonpath='{.spec.verifiers[?(@.name=="notation")].parameters.certificates[0].inline}' 2>/dev/null || \
  cat ~/.config/notation/localkeys/ratify-bats-test.crt 2>/dev/null || echo ""
}

# apply_v2_executor applies a v2 executor YAML file, replacing __NOTATION_CERT__
# placeholder with the actual notation certificate content.
apply_v2_executor() {
  local file="$1"
  local cert="$2"
  if [[ ! -f "$file" ]]; then
    echo "apply_v2_executor: file $file not found"
    return 1
  fi
  if [[ -z "$cert" ]]; then
    echo "apply_v2_executor: cert content is empty"
    return 1
  fi
  # Convert multi-line PEM to a JSON-escaped string (e.g. "-----BEGIN...\n...")
  # so it can be safely embedded in YAML as a quoted scalar.
  local json_cert
  json_cert=$(printf '%s' "$cert" | jq -Rs .)
  # Use perl for replacement — awk gsub interprets \n in replacement strings
  export __NOTATION_CERT_REPLACEMENT__="$json_cert"
  perl -pe 's/__NOTATION_CERT__/$ENV{"__NOTATION_CERT_REPLACEMENT__"}/g' "$file" | \
    kubectl apply --server-side --force-conflicts -f -
  local rc=$?
  unset __NOTATION_CERT_REPLACEMENT__
  return $rc
}