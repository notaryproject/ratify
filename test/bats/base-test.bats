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

BATS_TESTS_DIR=${BATS_TESTS_DIR:-test/bats/tests}
WAIT_TIME=60
SLEEP_TIME=1
RATIFY_NAMESPACE=gatekeeper-system
EXECUTOR_NAME=ratify-ratify-gatekeeper-provider-executor-1

# Extract notation cert from deployed executor (set once per file)
setup_file() {
    export NOTATION_CERT=$(get_notation_cert "${EXECUTOR_NAME}")
    export COSIGN_KEY=$(get_cosign_key "${EXECUTOR_NAME}")
    # Ensure ratify provider pod is fully ready and TLS is serving
    echo "Waiting for ratify provider to be fully ready..."
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=ratify-gatekeeper-provider -n ${RATIFY_NAMESPACE} --timeout=60s
    sleep 10
}

@test "base test without cert rotator" {
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo1 --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod initcontainer-pod --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod initcontainer-pod1 --namespace default --force --ignore-not-found=true'
    }
    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint_template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint.yaml
    assert_success
    sleep 5
    # validate executor status property shows success (retry for controller reconciliation)
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o jsonpath='{.status.succeeded}' | grep true"
    run kubectl run demo --namespace default --image=registry:5000/notation:signed
    assert_success
    run kubectl run demo1 --namespace default --image=registry:5000/notation:unsigned
    assert_failure

    # validate initContainers image
    run kubectl apply -f ./test/testdata/pod_initContainers_signed.yaml --namespace default
    assert_success

    run kubectl apply -f ./test/testdata/pod_initContainers_unsigned.yaml --namespace default
    assert_failure

    # validate ephemeralContainers image
    run kubectl debug demo --image=registry:5000/notation:signed --target=demo
    assert_success

    run kubectl debug demo --image=registry:5000/notation:unsigned --target=demo
    assert_failure
}

@test "test rendering notation verifier with modified trust policies settings" {
    teardown() {
        echo "cleaning up"
        rm -f notation-file1.crt
        rm -f notation-file2.crt
        rm -f notation-file3.crt
    }

    touch notation-file1.crt
    echo "fake cert 1" > notation-file1.crt
    touch notation-file2.crt
    echo "fake cert 2" > notation-file2.crt
    touch notation-file2.crt
    echo "fake cert 3" > notation-file3.crt

    # Happy path:
    # Capture Helm template output with notation configured via inline cert
    rendered=$(helm template multiple-trust-policies ./deployments/ratify-gatekeeper-provider \
        --set executor.scopes[0]="registry1.azurecr.io/" \
        --set featureFlags.RATIFY_CERT_ROTATION=true \
        --set notation.certs[0].provider=inline \
        --set notation.certs[0].cert="$(cat notation-file1.crt)" \
        --set notation.trustedIdentities[0]="x509.subject: cert identity 1" \
        --set stores[0].credential.provider=static)

    # the expected partial output (v2 Executor CRD format) - verify notation verifier is rendered
    expected_executor_name="multiple-trust-policies-ratify-gatekeeper-provider-executor-1"
    expected_verifier_type="type: notation"

    # Assert that the rendered Helm output contains the expected executor name and verifier type
    [[ "$rendered" == *"$expected_executor_name"* ]] || {
        echo "Rendered output does not contain the expected executor name."
        echo "Rendered output:"
        echo "$rendered"
        return 1
    }
    [[ "$rendered" == *"$expected_verifier_type"* ]] || {
        echo "Rendered output does not contain the expected verifier type."
        echo "Rendered output:"
        echo "$rendered"
        return 1
    }

    # Verify the executor has correct scopes
    [[ "$rendered" == *"registry1.azurecr.io/"* ]] || {
        echo "Rendered output does not contain the expected scope."
        echo "Rendered output:"
        echo "$rendered"
        return 1
    }

    # failure path: executor.scopes must not be empty
    run helm template multiple-trust-policies ./deployments/ratify-gatekeeper-provider \
        --set featureFlags.RATIFY_CERT_ROTATION=true \
        --set notation.certs[0].provider=inline \
        --set notation.certs[0].cert="$(cat notation-file1.crt)" \
        --set stores[0].credential.provider=static

    assert_failure

    # the expected error message
    expected_error="executor.scopes must not be empty"

    # Assert that the rendered Helm output contains the expected error message
    [[ "$output" == *"$expected_error"* ]]
}

@test "crd version test" {
    teardown() {
        echo "cleaning up"
        # restore original executor state
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor.yaml ${RATIFY_NAMESPACE}'
        rm -f original-executor.yaml
    }

    # save original executor state
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o yaml > original-executor.yaml"
    assert_success

    # verify executor CRD exists and reports correct apiVersion
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o yaml | grep 'apiVersion: config.ratify.dev/v2alpha1'"
    assert_success

    # verify the executor resource can be retrieved and has the expected kind
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o yaml | grep 'kind: Executor'"
    assert_success

    # re-apply the executor to verify it can be updated
    run restore_executor original-executor.yaml ${RATIFY_NAMESPACE}
    assert_success

    # verify the executor is still accessible after apply
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o yaml | grep 'apiVersion: config.ratify.dev/v2alpha1'"
    assert_success
}

@test "notation test" {
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo1 --namespace default --force --ignore-not-found=true'
    }
    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint_template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint.yaml
    assert_success
    sleep 5

    # validate executor status property shows success (retry for controller reconciliation)
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o jsonpath='{.status.succeeded}' | grep true"
    run kubectl run demo --namespace default --image=registry:5000/notation:signed
    assert_success

    run kubectl run demo1 --namespace default --image=registry:5000/notation:unsigned
    assert_failure
}

@test "notation test timestamping" {
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo-tsa --namespace default --force --ignore-not-found=true'

        # restore the original executor for other tests
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor-tsa.yaml ${RATIFY_NAMESPACE}'
        rm -f original-executor-tsa.yaml
    }

    # save original executor state
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o yaml > original-executor-tsa.yaml"
    assert_success

    # validate executor status property shows success (retry for controller reconciliation)
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o jsonpath='{.status.succeeded}' | grep true"

    # read the TSA root certificate as PEM and patch executor
    # patch executor to add TSA trust store and enable timestamp verification via v2 format
    run bash -c 'TSA_CERT=$(cat ./test/bats/tests/certificates/tsarootca.cer) && \
        kubectl get executors.config.ratify.dev/'"${EXECUTOR_NAME}"' -o json | \
        jq --arg tsa_cert "$TSA_CERT" '"'"'del(.metadata.managedFields, .metadata.resourceVersion, .metadata.uid, .metadata.creationTimestamp, .metadata.generation, .status) | .spec.verifiers = [(.spec.verifiers[] | if .name == "notation" or .name == "notation-1" then .parameters.certificates = [(.parameters.certificates[0]), {"type": "tsa", "inline": {"certs": $tsa_cert}}] else . end)]'"'"' | kubectl apply --server-side --force-conflicts -f -'
    assert_success
    sleep 10

    # verify that the image can now be run
    run kubectl run demo-tsa --namespace default --image=registry:5000/notation:tsa
    assert_success
}

@test "notation verification pass on CRL check with audit trust policy" {
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo --namespace default --force --ignore-not-found=true'

        # restore the original executor for other tests
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor-crl.yaml ${RATIFY_NAMESPACE}'
        rm -f original-executor-crl.yaml
    }

    # save original executor state
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o yaml > original-executor-crl.yaml"
    assert_success

    TARGET_IP=$(ip -4 addr show "eth0" | awk '/inet/ {print $2}' | cut -d'/' -f1)
    run kubectl patch deployment ratify-ratify-gatekeeper-provider -n ${RATIFY_NAMESPACE} --type='merge' -p '{"spec":{"template":{"spec":{"hostAliases":[{"ip":"'"${TARGET_IP}"'","hostnames":["yourhost"]}]}}}}'

    # wait for rollout to complete after adding hostAliases
    kubectl rollout status deployment/ratify-ratify-gatekeeper-provider -n ${RATIFY_NAMESPACE} --timeout=120s
    latest_pod=$(kubectl get pod -l app.kubernetes.io/name=ratify-gatekeeper-provider -n ${RATIFY_NAMESPACE} --sort-by=.metadata.creationTimestamp -o name | tail -n 1)
    kubectl wait --for=condition=ready -n ${RATIFY_NAMESPACE} ${latest_pod} --timeout=60s
    sleep 5

    # read the CRL root certificate as PEM and patch executor
    # patch executor to replace notation verifier with CRL root cert in v2 format
    run bash -c 'CRL_CERT=$(cat .staging/notation/crl-test/root.crt) && \
        kubectl get executors.config.ratify.dev/'"${EXECUTOR_NAME}"' -o json | \
        jq --arg crl_cert "$CRL_CERT" '"'"'del(.metadata.managedFields, .metadata.resourceVersion, .metadata.uid, .metadata.creationTimestamp, .metadata.generation, .status) | .spec.verifiers = [(.spec.verifiers[] | if .name == "notation" or .name == "notation-1" then .parameters.certificates = [{"type": "ca", "inline": {"certs": $crl_cert}}] else . end)]'"'"' | kubectl apply --server-side --force-conflicts -f -'
    assert_success
    sleep 10

    run kubectl run demo --namespace default --image=registry:5000/notation:crl
    assert_success
}

@test "notation test with certs across namespace" {
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo1 --namespace default --force --ignore-not-found=true'

        # restore original executor
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor-ns.yaml ${RATIFY_NAMESPACE}'
        rm -f original-executor-ns.yaml

        # delete the namespace-scoped executor
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete executors.config.ratify.dev/executor-new-namespace -n new-namespace --ignore-not-found=true'

        # delete new namespace
        run kubectl delete namespace new-namespace
        assert_success
    }

    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint_template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint.yaml
    assert_success
    sleep 5

    # save original executor state
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o yaml > original-executor-ns.yaml"
    assert_success

    # create a new namespace
    run kubectl create namespace new-namespace
    assert_success
    sleep 3

    # create a second executor with scope targeting the new namespace
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o json | jq '.metadata.name=\"executor-new-namespace\" | .metadata.namespace=\"new-namespace\" | .spec.scopes=[\"registry:5000/notation\"] | del(.metadata.resourceVersion) | del(.metadata.uid) | del(.metadata.creationTimestamp) | del(.status)' | kubectl apply -f -"
    assert_success
    sleep 3

    run kubectl run demo --namespace new-namespace --image=registry:5000/notation:signed
    assert_success

    run kubectl run demo1 --namespace new-namespace --image=registry:5000/notation:unsigned
    assert_failure
}

@test "cosign test" {
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod cosign-demo-key --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod cosign-demo-unsigned --namespace default --force --ignore-not-found=true'
    }
    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint_template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint.yaml
    assert_success
    sleep 5

    run kubectl run cosign-demo-key --namespace default --image=registry:5000/cosign:signed-key
    assert_success

    run kubectl run cosign-demo-unsigned --namespace default --image=registry:5000/cosign:unsigned
    assert_failure
}

@test "cosign legacy keyed test" {
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod cosign-demo-key --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod cosign-demo-unsigned --namespace default --force --ignore-not-found=true'

        # restore original executor
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor-cosign-legacy.yaml ${RATIFY_NAMESPACE}'
        rm -f original-executor-cosign-legacy.yaml
    }

    # save original executor state
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o yaml > original-executor-cosign-legacy.yaml"
    assert_success

    # replace executor with legacy cosign verifier format
    run apply_v2_executor ${BATS_TESTS_DIR}/config/v2_executor_cosign_legacy.yaml "${NOTATION_CERT}"
    assert_success
    sleep 5

    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint_template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint.yaml
    assert_success
    sleep 5

    run kubectl run cosign-demo-key --namespace default --image=registry:5000/cosign:signed-key
    assert_success

    run kubectl run cosign-demo-unsigned --namespace default --image=registry:5000/cosign:unsigned
    assert_failure
}

@test "cosign keyless test" {
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod cosign-demo-keyless --namespace default --force --ignore-not-found=true'
        # restore original executor
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor-cosign-keyless.yaml ${RATIFY_NAMESPACE}'
        rm -f original-executor-cosign-keyless.yaml
    }

    # save original executor state
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o yaml > original-executor-cosign-keyless.yaml"
    assert_success

    # replace executor with keyless cosign verifier and HTTPS store
    run apply_v2_executor ${BATS_TESTS_DIR}/config/v2_executor_cosign_keyless.yaml "${NOTATION_CERT}"
    assert_success
    sleep 5

    wait_for_process 20 10 'kubectl run cosign-demo-keyless --namespace default --image=wabbitnetworks.azurecr.io/test/cosign-image:signed-keyless'
}

@test "cosign legacy keyless test" {
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod cosign-demo-keyless --namespace default --force --ignore-not-found=true'
        # restore original executor
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor-cosign-legacy-keyless.yaml ${RATIFY_NAMESPACE}'
        rm -f original-executor-cosign-legacy-keyless.yaml
    }

    # save original executor state
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o yaml > original-executor-cosign-legacy-keyless.yaml"
    assert_success

    # replace executor with legacy keyless cosign verifier and HTTPS store
    run apply_v2_executor ${BATS_TESTS_DIR}/config/v2_executor_cosign_legacy_keyless.yaml "${NOTATION_CERT}"
    assert_success
    sleep 5

    wait_for_process 20 10 'kubectl run cosign-demo-keyless --namespace default --image=wabbitnetworks.azurecr.io/test/cosign-image:signed-keyless'
}

@test "validate crd add, replace and delete" {
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod crdtest --namespace default --force --ignore-not-found=true'
        # restore original executor
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor-crd.yaml ${RATIFY_NAMESPACE}'
        rm -f original-executor-crd.yaml
    }

    # save original executor state
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o yaml > original-executor-crd.yaml"
    assert_success

    echo "removing notation verifier from executor and validate deployment fails"
    # replace executor with notation verifier removed
    run kubectl apply --server-side --force-conflicts -f ${BATS_TESTS_DIR}/config/v2_executor_no_notation.yaml
    assert_success
    # wait for the httpserver cache to be invalidated
    sleep 15
    run kubectl run crdtest --namespace default --image=registry:5000/notation:signed
    assert_failure

    echo "Add notation verifier back and validate deployment succeeds"
    run restore_executor original-executor-crd.yaml ${RATIFY_NAMESPACE}
    assert_success

    # wait for the httpserver cache to be invalidated
    sleep 15
    run kubectl run crdtest --namespace default --image=registry:5000/notation:signed
    assert_success
}

@test "store crd status check" {
    teardown() {
        echo "cleaning up"
        # restore original executor
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor-store.yaml ${RATIFY_NAMESPACE}'
        rm -f original-executor-store.yaml
    }

    # save original executor state
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o yaml > original-executor-store.yaml"
    assert_success

    # replace executor with an invalid store config (invalid plugin version)
    run apply_v2_executor ${BATS_TESTS_DIR}/config/v2_executor_invalid_store.yaml "${NOTATION_CERT}"
    assert_success
    # wait for controller reconciliation
    sleep 5
    run bash -c "kubectl describe executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} | grep 'not registered'"
    assert_success
}

@test "configmap update test" {
    skip "Skipping test for now as we are no longer watching for configfile update in a K8s environment. This test ensures we are watching config file updates in a non-kub scenario"
    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint_template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint.yaml
    assert_success
    sleep 5
    run kubectl run demo2 --image=registry:5000/notation:signed
    assert_success

    run kubectl get configmaps ratify-configuration --namespace=${RATIFY_NAMESPACE} -o yaml >currentConfig.yaml
    run kubectl delete -f ${BATS_TESTS_DIR}/config/constraint.yaml

    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl replace --namespace=${RATIFY_NAMESPACE} -f ${BATS_TESTS_DIR}/configmap/invalidconfigmap.yaml"
    echo "Waiting for 150 second for configuration update"
    sleep 150

    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint.yaml
    assert_success
    run kubectl run demo3 --image=registry:5000/notation:signed
    echo "Current time after validate : $(date +"%T")"
    assert_failure

    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl replace --namespace=${RATIFY_NAMESPACE} -f currentConfig.yaml"
}

@test "validate mutation tag to digest" {
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod mutate-demo --namespace default --ignore-not-found=true'
    }

    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint_template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint.yaml
    assert_success
    sleep 5
    run kubectl run mutate-demo --namespace default --image=registry:5000/notation:signed
    assert_success
    result=$(kubectl get pod mutate-demo --namespace default -o json | jq -r ".spec.containers[0].image" | grep @sha)
    assert_mutate_success
}

@test "validate inline certificate store provider" {
    teardown() {
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo-alternate --namespace default --force --ignore-not-found=true'

        # restore original executor
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor-certstore.yaml ${RATIFY_NAMESPACE}'
        rm -f original-executor-certstore.yaml
    }

    # save original executor state
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o yaml > original-executor-certstore.yaml"
    assert_success

    # configure the default template/constraint
    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint_template_default.yaml
    assert_success
    run kubectl apply -f ./library/default/samples/constraint.yaml
    assert_success

    # verify that the image cannot be run due to an invalid cert
    run kubectl run demo-alternate --namespace default --image=registry:5000/notation:signed-alternate
    assert_failure

    # patch executor to use alternate inline certificate in notation verifier (v2 format)
    run bash -c 'ALT_CERT=$(cat ~/.config/notation/truststore/x509/ca/alternate-cert/alternate-cert.crt) && \
        kubectl get executors.config.ratify.dev/'"${EXECUTOR_NAME}"' -n '"${RATIFY_NAMESPACE}"' -o json | \
        jq --arg alt_cert "$ALT_CERT" '"'"'
            .spec.verifiers = [(.spec.verifiers[] | if .name == "notation" or .name == "notation-1" then
                .parameters.certificates = [{"type": "ca", "inline": {"certs": $alt_cert}}]
            else . end)]
        '"'"' | kubectl apply --server-side --force-conflicts -f -'
    assert_success
    sleep 10

    # verify that the image can now be run
    run kubectl run demo-alternate --namespace default --image=registry:5000/notation:signed-alternate
    assert_success
}

@test "validate inline key management provider" {
    teardown() {
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo-alternate --namespace default --force --ignore-not-found=true'

        # restore the original executor for other tests
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor-kmp.yaml ${RATIFY_NAMESPACE}'
        rm -f original-executor-kmp.yaml
    }

    # save original executor state
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o yaml > original-executor-kmp.yaml"
    assert_success

    # configure the default template/constraint
    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint_template.yaml
    assert_success
    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint.yaml
    assert_success

    # verify that the image cannot be run due to an invalid cert
    sleep 10
    run kubectl run demo-alternate --namespace default --image=registry:5000/notation:signed-alternate
    assert_failure
    sleep 10

    # read the alternate certificate content as PEM
    # patch executor to include both the default and alternate certs inline
    run bash -c 'ALT_CERT=$(cat ~/.config/notation/truststore/x509/ca/alternate-cert/alternate-cert.crt) && \
        ORIG_CERT=$(cat ~/.config/notation/localkeys/ratify-bats-test.crt) && \
        kubectl get executors.config.ratify.dev/'"${EXECUTOR_NAME}"' -n '"${RATIFY_NAMESPACE}"' -o json | \
        jq --arg alt_cert "$ALT_CERT" --arg orig_cert "$ORIG_CERT" '"'"'
            .spec.verifiers = [(.spec.verifiers[] | if .name == "notation" or .name == "notation-1" then
                .parameters.certificates = [{"type": "ca", "inline": {"certs": $orig_cert}}, {"type": "ca", "inline": {"certs": $alt_cert}}]
            else . end)]
        '"'"' | kubectl apply --server-side --force-conflicts -f -'
    assert_success
    kubectl rollout restart deployment/ratify-ratify-gatekeeper-provider -n ${RATIFY_NAMESPACE}
    kubectl rollout status deployment/ratify-ratify-gatekeeper-provider -n ${RATIFY_NAMESPACE} --timeout=120s
    latest_pod=$(kubectl get pod -l app.kubernetes.io/name=ratify-gatekeeper-provider -n ${RATIFY_NAMESPACE} --sort-by=.metadata.creationTimestamp -o name | tail -n 1)
    kubectl wait --for=condition=ready -n ${RATIFY_NAMESPACE} ${latest_pod} --timeout=60s

    # verify that the image can now be run
    run kubectl run demo-alternate --namespace default --image=registry:5000/notation:signed-alternate
    assert_success
}

@test "validate inline key management provider with inline certificate store" {
    # this test validates that executor verifier config with inline cert works correctly
    # and that the executor status remains successful
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo1 --namespace default --force --ignore-not-found=true'

        # restore original executor
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor-kmp-certstore.yaml ${RATIFY_NAMESPACE}'
        rm -f original-executor-kmp-certstore.yaml
    }

    # save original executor state
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o yaml > original-executor-kmp-certstore.yaml"
    assert_success

    # configure the default template/constraint
    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint_template.yaml
    assert_success
    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint.yaml
    assert_success

    # validate executor status property shows success (retry for controller reconciliation)
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o jsonpath='{.status.succeeded}' | grep true"
    run kubectl run demo --namespace default --image=registry:5000/notation:signed
    assert_success

    sleep 10

    # patch executor with an additional cert in inline (executor should still reconcile successfully)
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o json | jq '
        del(.metadata.managedFields, .metadata.resourceVersion, .metadata.uid, .metadata.creationTimestamp, .metadata.generation, .status) |
        .spec.verifiers = [(.spec.verifiers[] | if .name == \"notation\" or .name == \"notation-1\" then
            .parameters.trustedIdentities = [\"*\"]
        else . end)]
    ' | kubectl apply --server-side --force-conflicts -f -"
    assert_success
    sleep 5
    # validate executor status still shows success
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o jsonpath='{.status.succeeded}' | grep true"
    # verification should succeed as the cert config is still valid
    run kubectl run demo1 --namespace default --image=registry:5000/notation:signed
    assert_success
}

@test "validate K8s secrets ORAS auth provider" {
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo --namespace default --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo1 --namespace default --ignore-not-found=true'
        # restore original executor
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor-k8s-auth.yaml ${RATIFY_NAMESPACE}'
        rm -f original-executor-k8s-auth.yaml
    }

    # save original executor state
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o yaml > original-executor-k8s-auth.yaml"
    assert_success

    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint_template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint.yaml
    assert_success
    sleep 5

    # replace executor with K8s secret auth provider config
    run apply_v2_executor ${BATS_TESTS_DIR}/config/v2_executor_k8s_secret_auth.yaml "${NOTATION_CERT}"
    assert_success
    sleep 5
    run kubectl run demo --namespace default --image=registry:5000/notation:signed
    assert_success
    run kubectl run demo1 --namespace default --image=registry:5000/notation:unsigned
    assert_failure
}

@test "validate image signed by leaf cert" {
    teardown() {
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo-leaf --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo-leaf2 --namespace default --force --ignore-not-found=true'

        # restore the original executor for other tests
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor-leaf.yaml ${RATIFY_NAMESPACE}'
        rm -f original-executor-leaf.yaml
    }

    # save original executor state
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o yaml > original-executor-leaf.yaml"
    assert_success

    # configure the default template/constraint
    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint_template.yaml
    assert_success
    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint.yaml
    assert_success

    # read the root certificate content as PEM
    # patch executor to use root cert in verifier config (v2 format)
    run bash -c 'ROOT_CERT=$(cat ~/.config/notation/truststore/x509/ca/leaf-test/root.crt) && \
        kubectl get executors.config.ratify.dev/'"${EXECUTOR_NAME}"' -n '"${RATIFY_NAMESPACE}"' -o json | \
        jq --arg root_cert "$ROOT_CERT" '"'"'
            .spec.verifiers = [(.spec.verifiers[] | if .name == "notation" or .name == "notation-1" then
                .parameters.certificates = [{"type": "ca", "inline": {"certs": $root_cert}}]
            else . end)]
        '"'"' | kubectl apply --server-side --force-conflicts -f -'
    assert_success

    # verify that the image can be run with a root cert
    run kubectl run demo-leaf --namespace default --image=registry:5000/notation:leafSigned
    assert_success

    # read the leaf certificate content as PEM
    # patch executor to use leaf cert directly (v2 format)
    run bash -c 'LEAF_CERT=$(cat ~/.config/notation/truststore/x509/ca/leaf-test/leaf.crt) && \
        kubectl get executors.config.ratify.dev/'"${EXECUTOR_NAME}"' -n '"${RATIFY_NAMESPACE}"' -o json | \
        jq --arg leaf_cert "$LEAF_CERT" '"'"'
            .spec.verifiers = [(.spec.verifiers[] | if .name == "notation" or .name == "notation-1" then
                .parameters.certificates = [{"type": "ca", "inline": {"certs": $leaf_cert}}]
            else . end)]
        '"'"' | kubectl apply --server-side --force-conflicts -f -'
    assert_success
    kubectl rollout restart deployment/ratify-ratify-gatekeeper-provider -n ${RATIFY_NAMESPACE}
    kubectl rollout status deployment/ratify-ratify-gatekeeper-provider -n ${RATIFY_NAMESPACE} --timeout=120s
    latest_pod=$(kubectl get pod -l app.kubernetes.io/name=ratify-gatekeeper-provider -n ${RATIFY_NAMESPACE} --sort-by=.metadata.creationTimestamp -o name | tail -n 1)
    kubectl wait --for=condition=ready -n ${RATIFY_NAMESPACE} ${latest_pod} --timeout=60s

    # verify that the image cannot be run with a leaf cert
    run kubectl run demo-leaf2 --namespace default --image=registry:5000/notation:leafSigned
    assert_failure
}

@test "validate ratify/gatekeeper tls cert rotation" {
    skip "requires TLS rotation setup from CI infrastructure"
    teardown() {
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo --namespace default --force --ignore-not-found=true'
    }

    # update Providers to use the new CA
    run kubectl get Provider ratify-mutation-provider -o json | jq --arg ca "$(cat .staging/rotation/ca.crt | base64)" '.spec.caBundle=$ca' | kubectl replace -f -
    run kubectl get Provider ratify-provider -o json | jq --arg ca "$(cat .staging/rotation/ca.crt | base64)" '.spec.caBundle=$ca' | kubectl replace -f -

    # update the ratify tls secret to use the new tls cert and key
    run kubectl get secret ratify-tls -n ${RATIFY_NAMESPACE} -o json | jq --arg cert "$(cat .staging/rotation/server.crt | base64)" --arg key "$(cat .staging/rotation/server.key | base64)" '.data["tls.key"]=$key | .data["tls.crt"]=$cert' | kubectl replace -f -

    # update the gatekeeper webhook server tls secret to use the new cert bundle
    run kubectl get Secret gatekeeper-webhook-server-cert -n ${RATIFY_NAMESPACE} -o json | jq --arg caCert "$(cat .staging/rotation/gatekeeper/ca.crt | base64)" --arg caKey "$(cat .staging/rotation/gatekeeper/ca.key | base64)" --arg tlsCert "$(cat .staging/rotation/gatekeeper/server.crt | base64)" --arg tlsKey "$(cat .staging/rotation/gatekeeper/server.key | base64)" '.data["ca.crt"]=$caCert | .data["ca.key"]=$caKey | .data["tls.crt"]=$tlsCert | .data["tls.key"]=$tlsKey' | kubectl replace -f -

    # volume projection can take up to 90 seconds
    sleep 100

    # verify that the verification succeeds
    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint_template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint.yaml
    assert_success
    sleep 5
    run kubectl run demo --namespace default --image=registry:5000/notation:signed
    assert_success
}

@test "namespaced notation/cosign verifiers test" {
    teardown() {
        echo "cleaning up"
        # delete namespace-scoped executors
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete executors.config.ratify.dev/executor-notation-default -n default --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete executors.config.ratify.dev/executor-cosign-default -n default --ignore-not-found=true'

        # restore original executor
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor-namespaced.yaml ${RATIFY_NAMESPACE}'
        rm -f original-executor-namespaced.yaml

        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod notation-demo --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod notation-demo1 --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod cosign-demo-key --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod cosign-demo-unsigned --namespace default --force --ignore-not-found=true'
    }

    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint_template.yaml
    run kubectl apply -f ${BATS_TESTS_DIR}/config/constraint.yaml
    sleep 3

    # save original executor state
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -n ${RATIFY_NAMESPACE} -o yaml > original-executor-namespaced.yaml"
    assert_success

    # create a namespace-scoped executor for notation verification in default namespace
    run apply_v2_executor ${BATS_TESTS_DIR}/config/v2_executor_namespace_notation.yaml "${NOTATION_CERT}"
    assert_success

    # remove notation verifier from cluster executor to force use of namespace-scoped one
    run kubectl apply --server-side --force-conflicts -f ${BATS_TESTS_DIR}/config/v2_executor_no_notation.yaml
    assert_success
    sleep 5

    # validate notation images using namespace-scoped executor
    run kubectl run notation-demo --namespace default --image=registry:5000/notation:signed
    assert_success

    run kubectl run notation-demo1 --namespace default --image=registry:5000/notation:unsigned
    assert_failure

    # create a namespace-scoped executor for cosign verification in default namespace
    run apply_v2_executor ${BATS_TESTS_DIR}/config/v2_executor_namespace_cosign.yaml "${NOTATION_CERT}"
    assert_success

    # remove cosign verifier from cluster executor
    run apply_v2_executor ${BATS_TESTS_DIR}/config/v2_executor_no_verifiers.yaml "${NOTATION_CERT}"
    assert_success
    sleep 5

    # validate cosign images using namespace-scoped executor
    run kubectl run cosign-demo-key --namespace default --image=registry:5000/cosign:signed-key
    assert_success

    run kubectl run cosign-demo-unsigned --namespace default --image=registry:5000/cosign:unsigned
    assert_failure
}
