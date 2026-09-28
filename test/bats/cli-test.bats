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

    # TODO: the v1 suite additionally shifted the system clock forward 2 days to
    # prove that verification fails without the TSA root cert and succeeds with
    # it. Re-add that expired-cert variant once it can run without `sudo date`.
}

@test "notation verifier leaf cert test" {
    verifiers='[{"name":"notation-1","type":"notation","parameters":{"certificates":[{"type":"ca","files":["'"${NOTATION_LEAF_CA_CERT}"'"]}]}}]'
    policy="$(threshold_policy '[{"verifierName":"notation-1"}]' 1)"
    render_config "${RATIFY_CONFIG_DIR}/notation_leaf.json" "${verifiers}" "${policy}"

    run bin/ratify verify -c "${RATIFY_CONFIG_DIR}/notation_leaf.json" -s ${TEST_REGISTRY}/notation:leafSigned
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" == *"SUCCEEDED"* ]]

    # TODO: the v1 test also asserted that trusting only the leaf certificate
    # fails. The v2 notation verifier has no equivalent of the v1
    # `config_notation_leaf_cert.json` trust-store layout yet, so the negative
    # case is not covered here.
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
    # entry (cosign sign --tlog-upload=false). Verifying such a fully offline,
    # key-signed image requires both ignoreTLog (no log entry to look up) and
    # ignoreObserverTimestamps (no RFC3161 / SignedEntryTimestamp to check). The
    # inline key provider is used because the "files" provider expects x509
    # certificates rather than a bare cosign public key. jq safely embeds the
    # multi-line PEM into the JSON configuration.
    verifiers="$(bin/jq -nc --arg reg "${TEST_REGISTRY}" --arg key "${pub}" \
        '[{name:"cosign-1",type:"cosign",parameters:{trustPolicies:[{scopes:[$reg],ignoreTLog:true,ignoreObserverTimestamps:true,keys:{inline:{keys:$key}}}]}}]')"
    policy="$(threshold_policy '[{"verifierName":"cosign-1"}]' 1)"
    render_config "${RATIFY_CONFIG_DIR}/cosign.json" "${verifiers}" "${policy}"

    run bin/ratify verify -c "${RATIFY_CONFIG_DIR}/cosign.json" -s ${TEST_REGISTRY}/cosign:signed-key
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" == *"SUCCEEDED"* ]]

    run bin/ratify verify -c "${RATIFY_CONFIG_DIR}/cosign.json" -s ${TEST_REGISTRY}/cosign:unsigned
    echo "$output"
    [ "$status" -ne 0 ]
    [[ "$output" == *"FAILED"* ]]
}

# ---------------------------------------------------------------------------
# Scenarios covered by the v1 CLI tests that the v2 CLI does not support yet.
#
# These are intentionally kept (and skipped) rather than deleted so the missing
# coverage stays visible. Each one should be re-enabled as the corresponding v2
# capability lands.
# ---------------------------------------------------------------------------

@test "cosign keyless verifier test" {
    skip "TODO: keyless verification (Fulcio/Rekor) against wabbitnetworks.azurecr.io is not wired up for the v2 CLI e2e yet."
}

@test "notation verifier crl test" {
    skip "TODO: the v2 notation verifier does not expose CRL revocation/cache configuration (config_notation_crl*.json in v1) yet."
}

@test "notation verifier with type test" {
    skip "TODO: the v2 verifier configuration has no equivalent of the v1 artifact 'type' field."
}

@test "notation verifier leaf cert with rego policy" {
    skip "TODO: the v2 CLI only ships the threshold-policy enforcer; the rego policy provider is not available yet."
}

@test "licensechecker verifier test" {
    skip "TODO: plugin verifiers are being migrated to github.com/notaryproject/ratify-verifier-go and are not shipped by the v2 CLI."
}

@test "licensechecker verifier with type test" {
    skip "TODO: plugin verifiers are being migrated to github.com/notaryproject/ratify-verifier-go and are not shipped by the v2 CLI."
}

@test "sbom verifier test" {
    skip "TODO: plugin verifiers are being migrated to github.com/notaryproject/ratify-verifier-go and are not shipped by the v2 CLI."
}

@test "schemavalidator verifier test" {
    skip "TODO: plugin verifiers are being migrated to github.com/notaryproject/ratify-verifier-go and are not shipped by the v2 CLI."
}

@test "vulnerabilityreport verifier test" {
    skip "TODO: plugin verifiers are being migrated to github.com/notaryproject/ratify-verifier-go and are not shipped by the v2 CLI."
}

@test "sbom/notary/cosign/licensechecker verifiers test" {
    skip "TODO: depends on the plugin verifiers above; re-enable once they are available to the v2 CLI."
}

@test "dynamic plugin verifier test" {
    skip "TODO: the v2 CLI does not support dynamic plugin download (RATIFY_EXPERIMENTAL_DYNAMIC_PLUGINS)."
}

@test "dynamic plugin store test" {
    skip "TODO: the v2 CLI does not support dynamic plugin download (RATIFY_EXPERIMENTAL_DYNAMIC_PLUGINS)."
}
