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
# Required environment (provided by the `test-e2e-cli-v2` Makefile target):
#   TEST_REGISTRY           local registry hosting the notation fixtures
#   TEST_REGISTRY_USERNAME  registry username
#   TEST_REGISTRY_PASSWORD  registry password
#   NOTATION_CA_CERT        path to the notation signing certificate

setup() {
    RATIFY_CONFIG_DIR="$(mktemp -d)"
    cat >"${RATIFY_CONFIG_DIR}/notation.json" <<EOF
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
                        "credential": {
                            "provider": "static",
                            "username": "${TEST_REGISTRY_USERNAME}",
                            "password": "${TEST_REGISTRY_PASSWORD}"
                        }
                    }
                }
            ],
            "verifiers": [
                {
                    "name": "notation-1",
                    "type": "notation",
                    "parameters": {
                        "certificates": [
                            {
                                "type": "ca",
                                "files": [
                                    "${NOTATION_CA_CERT}"
                                ]
                            }
                        ]
                    }
                }
            ],
            "policyEnforcer": {
                "type": "threshold-policy",
                "parameters": {
                    "policy": {
                        "rules": [
                            {
                                "verifierName": "notation-1"
                            }
                        ],
                        "threshold": 1
                    }
                }
            }
        }
    ]
}
EOF
}

teardown() {
    rm -rf "${RATIFY_CONFIG_DIR}"
}

@test "cli version prints build information" {
    run bin/ratify version
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "cli verify succeeds for a notation signed artifact" {
    run bin/ratify verify -c "${RATIFY_CONFIG_DIR}/notation.json" -s ${TEST_REGISTRY}/notation:signed
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" == *"SUCCEEDED"* ]]
}

@test "cli verify fails for an unsigned artifact" {
    run bin/ratify verify -c "${RATIFY_CONFIG_DIR}/notation.json" -s ${TEST_REGISTRY}/notation:unsigned
    echo "$output"
    [ "$status" -ne 0 ]
    [[ "$output" == *"FAILED"* ]]
}

@test "cli verify emits json output for a signed artifact" {
    run bin/ratify verify -c "${RATIFY_CONFIG_DIR}/notation.json" -s ${TEST_REGISTRY}/notation:signed -o json
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" == *"\"succeeded\": true"* ]]
}
