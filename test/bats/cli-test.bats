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

#!/usr/bin/env bats

load helpers

@test "notation verifier test" {
    run bin/ratify verify -c $RATIFY_DIR/config.json -s $TEST_REGISTRY/notation:signed
    assert_cmd_verify_success

    run bin/ratify verify -c $RATIFY_DIR/config.json -s $TEST_REGISTRY/notation:unsigned
    assert_cmd_verify_failure

    run bin/ratify verify -c $RATIFY_DIR/config_tsa.json -s $TEST_REGISTRY/notation:tsa
    assert_cmd_verify_success
}

@test "notation verifier leaf cert test" {
    run bin/ratify verify -c $RATIFY_DIR/config_notation_root_cert.json -s $TEST_REGISTRY/notation:leafSigned
    assert_cmd_verify_success

    run bin/ratify verify -c $RATIFY_DIR/config_notation_leaf_cert.json -s $TEST_REGISTRY/notation:leafSigned
    assert_cmd_verify_failure
}

@test "notation verifier crl test" {
    sudo sed -i '1i 127.0.0.1 yourhost' /etc/hosts
    revoke_crl

    run bin/ratify verify -c $RATIFY_DIR/config_notation_crl.json -s $TEST_REGISTRY/notation:crl
    assert_cmd_verify_failure
    
    check_crl_cache_created
    
    delete_crl_cache
    check_crl_cache_deleted
    unrevoke_crl

    run bin/ratify verify -c $RATIFY_DIR/config_notation_crl_cache_disabled.json -s $TEST_REGISTRY/notation:crl
    assert_cmd_verify_success

    check_crl_cache_deleted
}

@test "notation verifier multiarch test" {
    run bin/ratify verify -c $RATIFY_DIR/config.json -s $TEST_REGISTRY/notation:multiarch-signed
    assert_cmd_verify_success

    run bin/ratify verify -c $RATIFY_DIR/config.json -s $TEST_REGISTRY/notation:multiarch-unsigned
    assert_cmd_verify_failure
}

@test "notation verifier with type test" {
    run bin/ratify verify -c $RATIFY_DIR/config_notation_verifier_with_type.json -s $TEST_REGISTRY/notation:leafSigned
    assert_cmd_verify_success_with_type
}

@test "multiple notation verifiers test" {
    run bin/ratify verify -c $RATIFY_DIR/config_multiple_notation_verifiers.json -s $TEST_REGISTRY/notation:leafSigned
    assert_cmd_multi_verifier_success
}

@test "notation verifier leaf cert with rego policy" {
    run bin/ratify verify -c $RATIFY_DIR/config_rego_policy_notation_root_cert.json -s $TEST_REGISTRY/notation:leafSigned
    assert_cmd_verify_success

    run bin/ratify verify -c $RATIFY_DIR/config_rego_policy_notation_leaf_cert.json -s $TEST_REGISTRY/notation:leafSigned
    assert_cmd_verify_failure
}

@test "cosign verifier test" {
    run bin/ratify verify -c $RATIFY_DIR/config.json -s $TEST_REGISTRY/cosign:signed-key
    assert_cmd_verify_success

    run bin/ratify verify -c $RATIFY_DIR/cosign_keyless_config.json -s wabbitnetworks.azurecr.io/test/cosign-image:signed-keyless
    assert_cmd_verify_success
    assert_cmd_cosign_keyless_verify_bundle_success

    run bin/ratify verify -c $RATIFY_DIR/config.json -s $TEST_REGISTRY/cosign:unsigned
    assert_cmd_verify_failure
}

@test "licensechecker verifier test" {
    run bin/ratify verify -c $RATIFY_DIR/complete_licensechecker_config.json -s $TEST_REGISTRY/licensechecker:v0
    assert_cmd_verify_success

    run bin/ratify verify -c $RATIFY_DIR/partial_licensechecker_config.json -s $TEST_REGISTRY/licensechecker:v0
    assert_cmd_verify_failure
}

@test "licensechecker verifier with type test" {
    run bin/ratify verify -c $RATIFY_DIR/config_external_verifier_with_type.json -s $TEST_REGISTRY/licensechecker:v0
    assert_cmd_verify_success_with_type
}

@test "sbom verifier test" {
    # run with mismatch plugin version config should fail
    run bin/ratify verify -c $RATIFY_DIR/sbom_version_mismatch.json -s $TEST_REGISTRY/sbom:v0
    assert_cmd_verify_failure

    # run with deny license config should fail
    run bin/ratify verify -c $RATIFY_DIR/sbom_denylist_config_licensematch.json -s $TEST_REGISTRY/sbom:v0
    assert_cmd_verify_failure

    # run with deny package with unmatched version should succeed
    run bin/ratify verify -c $RATIFY_DIR/sbom_denylist_config_nomatch.json -s $TEST_REGISTRY/sbom:v0
    assert_cmd_verify_success

    # run with deny package with matched name and version should fail
    run bin/ratify verify -c $RATIFY_DIR/sbom_denylist_config_packagematch.json -s $TEST_REGISTRY/sbom:v0
    assert_cmd_verify_failure


    # Notes: test would fail if sbom/notary types are explicitly specified in the policy
    run bin/ratify verify -c $RATIFY_DIR/config.json -s $TEST_REGISTRY/sbom:v0
    assert_cmd_verify_success

    run bin/ratify verify -c $RATIFY_DIR/config.json -s $TEST_REGISTRY/sbom:unsigned
    assert_cmd_verify_failure
}

@test "schemavalidator verifier test" {
    run bin/ratify verify -c $RATIFY_DIR/schemavalidator_config.json -s $TEST_REGISTRY/schemavalidator:v0
    assert_cmd_verify_success
}

@test "vulnerabilityreport verifier test" {
    run bin/ratify verify -c $RATIFY_DIR/vulnerabilityreport_config.json -s $TEST_REGISTRY/vulnerabilityreport:v0
    assert_cmd_verify_success
}

@test "sbom/notary/cosign/licensechecker verifiers test" {
    run bin/ratify verify -c $RATIFY_DIR/config.json -s $TEST_REGISTRY/all:v0
    assert_cmd_verify_success
}

@test "dynamic plugin verifier test" {
    # dynamic plugins disabled by default
    run bash -c "bin/ratify verify -c $RATIFY_DIR/dynamic_plugins_config.json -s  $TEST_REGISTRY/all:v0 2>&1 >/dev/null | grep 'dynamic plugins are currently disabled'"
    assert_success

    # dynamic plugins enabled with feature flag
    run bash -c "RATIFY_EXPERIMENTAL_DYNAMIC_PLUGINS=1 bin/ratify verify -c $RATIFY_DIR/dynamic_plugins_config.json -s  $TEST_REGISTRY/all:v0 2>&1 >/dev/null | grep 'downloaded verifier plugin dynamic from .* to .*'"
    assert_success

    # ensure the plugin is downloaded and marked executable
    test -x $RATIFY_DIR/plugins/dynamic
    assert_success
}

@test "dynamic plugin store test" {
    # dynamic plugins disabled by default
    run bash -c "bin/ratify verify -c $RATIFY_DIR/dynamic_plugins_config.json -s  $TEST_REGISTRY/all:v0 2>&1 >/dev/null | grep 'dynamic plugins are currently disabled'"
    assert_success

    # dynamic plugins enabled with feature flag
    run bash -c "RATIFY_EXPERIMENTAL_DYNAMIC_PLUGINS=1 bin/ratify verify -c $RATIFY_DIR/dynamic_plugins_config.json -s  $TEST_REGISTRY/all:v0 2>&1 >/dev/null | grep 'downloaded store plugin dynamicstore from .* to .*'"
    assert_success

    # ensure the plugin is downloaded and marked executable
    test -x $RATIFY_DIR/plugins/dynamicstore
    assert_success
}

@test "notation verifier tsa test" {
    teardown() {
        # reset current_time
        run sudo date -s "-2 days"
    }

    # update system date to expire the cert and trigger timestamp verification
    run sudo date -s "2 days" 

    run bin/ratify verify -c $RATIFY_DIR/config.json -s $TEST_REGISTRY/notation:tsa
    assert_cmd_verify_failure

    run bin/ratify verify -c $RATIFY_DIR/config_tsa.json -s $TEST_REGISTRY/notation:tsa
    assert_cmd_verify_success
}