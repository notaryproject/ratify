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

#!/usr/bin/env bats

# End-to-end tests for the v2 `ratify` CLI (cmd/ratify).
#
# Required environment (provided by the `test-e2e-cli` Makefile target):
#   TEST_REGISTRY           local registry hosting the fixtures
#   TEST_REGISTRY_USERNAME  registry username
#   TEST_REGISTRY_PASSWORD  registry password
#   NOTATION_CA_CERT        notation CA signing certificate (default key)
#   NOTATION_TSA_ROOT_CERT  TSA root certificate for timestamped signatures
#   NOTATION_LEAF_CA_CERT   root CA of the notation leaf-signing chain
#   COSIGN_PUB_KEY          cosign public key used to sign cosign:signed-key

setup() {
    RATIFY_CONFIG_DIR="$(mktemp -d)"
}

teardown() {
    rm -rf "${RATIFY_CONFIG_DIR}"
}

# render_config <outfile> <verifiers-json> <policy-json>
#
# Writes a ratify v2 configuration scoped to ${TEST_REGISTRY} using the local
# registry-store (static credential over plain HTTP) with the supplied verifiers
# and policy enforcer.
render_config() {
    cat >"$1" <<EOF
{
    "executors": [
        {
            "scopes": [
                "${TEST_REGISTRY}"
            ],
            "stores": [
                {
                    "type": "registry-store",
                    "parameters": {
                        "plainHttp": true,
                        "allowCosignTag": true,
                        "credential": {
                            "provider": "static",
                            "username": "${TEST_REGISTRY_USERNAME}",
                            "password": "${TEST_REGISTRY_PASSWORD}"
                        }
                    }
                }
            ],
            "verifiers": $2,
            "policyEnforcer": $3
        }
    ]
}
EOF
}

# threshold_policy <rules-json> <threshold>
threshold_policy() {
    echo "{ \"type\": \"threshold-policy\", \"parameters\": { \"policy\": { \"rules\": $1, \"threshold\": $2 } } }"
}

@test "cli version prints build information" {
    run bin/ratify version
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "notation verifier test" {
    verifiers='[{"name":"notation-1","type":"notation","parameters":{"certificates":[{"type":"ca","files":["'"${NOTATION_CA_CERT}"'"]}]}}]'
    policy="$(threshold_policy '[{"verifierName":"notation-1"}]' 1)"
    render_config "${RATIFY_CONFIG_DIR}/notation.json" "${verifiers}" "${policy}"

    run bin/ratify verify -c "${RATIFY_CONFIG_DIR}/notation.json" -s ${TEST_REGISTRY}/notation:signed
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" == *"SUCCEEDED"* ]]

    run bin/ratify verify -c "${RATIFY_CONFIG_DIR}/notation.json" -s ${TEST_REGISTRY}/notation:unsigned
    echo "$output"
    [ "$status" -ne 0 ]
    [[ "$output" == *"FAILED"* ]]
}

@test "notation verifier json output" {
    verifiers='[{"name":"notation-1","type":"notation","parameters":{"certificates":[{"type":"ca","files":["'"${NOTATION_CA_CERT}"'"]}]}}]'
    policy="$(threshold_policy '[{"verifierName":"notation-1"}]' 1)"
    render_config "${RATIFY_CONFIG_DIR}/notation.json" "${verifiers}" "${policy}"

    run bin/ratify verify -c "${RATIFY_CONFIG_DIR}/notation.json" -s ${TEST_REGISTRY}/notation:signed -o json
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" == *"\"succeeded\": true"* ]]
}

@test "notation verifier tsa test" {
    verifiers='[{"name":"notation-1","type":"notation","parameters":{"certificates":[{"type":"ca","files":["'"${NOTATION_CA_CERT}"'"]},{"type":"tsa","files":["'"${NOTATION_TSA_ROOT_CERT}"'"]}]}}]'
    policy="$(threshold_policy '[{"verifierName":"notation-1"}]' 1)"
    render_config "${RATIFY_CONFIG_DIR}/notation_tsa.json" "${verifiers}" "${policy}"

    run bin/ratify verify -c "${RATIFY_CONFIG_DIR}/notation_tsa.json" -s ${TEST_REGISTRY}/notation:tsa
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" == *"SUCCEEDED"* ]]
}

@test "notation verifier leaf cert test" {
    verifiers='[{"name":"notation-1","type":"notation","parameters":{"certificates":[{"type":"ca","files":["'"${NOTATION_LEAF_CA_CERT}"'"]}]}}]'
    policy="$(threshold_policy '[{"verifierName":"notation-1"}]' 1)"
    render_config "${RATIFY_CONFIG_DIR}/notation_leaf.json" "${verifiers}" "${policy}"

    run bin/ratify verify -c "${RATIFY_CONFIG_DIR}/notation_leaf.json" -s ${TEST_REGISTRY}/notation:leafSigned
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" == *"SUCCEEDED"* ]]
}

@test "multiple notation verifiers test" {
    verifiers='[{"name":"notation-1","type":"notation","parameters":{"certificates":[{"type":"ca","files":["'"${NOTATION_CA_CERT}"'"]}]}},{"name":"notation-2","type":"notation","parameters":{"certificates":[{"type":"ca","files":["'"${NOTATION_CA_CERT}"'"]}]}}]'
    policy="$(threshold_policy '[{"verifierName":"notation-1"},{"verifierName":"notation-2"}]' 2)"
    render_config "${RATIFY_CONFIG_DIR}/notation_multi.json" "${verifiers}" "${policy}"

    run bin/ratify verify -c "${RATIFY_CONFIG_DIR}/notation_multi.json" -s ${TEST_REGISTRY}/notation:signed
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" == *"SUCCEEDED"* ]]
}

@test "cosign verifier test" {
    local pub
    pub="$(cat "${COSIGN_PUB_KEY}")"
    # The cosign fixture is signed with a local key pair and no transparency log
    # entry (--tlog-upload=false), so verification must ignore the tlog. The
    # inline key provider is used because the "files" provider expects x509
    # certificates rather than a bare cosign public key. jq safely embeds the
    # multi-line PEM into the JSON configuration.
    verifiers="$(bin/jq -nc --arg reg "${TEST_REGISTRY}" --arg key "${pub}" \
        '[{name:"cosign-1",type:"cosign",parameters:{trustPolicies:[{scopes:[$reg],ignoreTLog:true,keys:{inline:{keys:$key}}}]}}]')"
    policy="$(threshold_policy '[{"verifierName":"cosign-1"}]' 1)"
    render_config "${RATIFY_CONFIG_DIR}/cosign.json" "${verifiers}" "${policy}"

    run bin/ratify verify -c "${RATIFY_CONFIG_DIR}/cosign.json" -s ${TEST_REGISTRY}/cosign:signed-key
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" == *"SUCCEEDED"* ]]
}
