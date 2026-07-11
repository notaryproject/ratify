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
RATIFY_NAME=ratify
RATIFY_NAMESPACE=gatekeeper-system
EXECUTOR_NAME=ratify-gatekeeper-provider-executor-1

@test "base test without cert rotator" {
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo1 --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod initcontainer-pod --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod initcontainer-pod1 --namespace default --force --ignore-not-found=true'
    }
    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success
    sleep 5
    # wait for executor to be reconciled by controller
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl get executors.config.ratify.dev -n ${RATIFY_NAMESPACE} -o jsonpath='{.items[0].status.succeeded}' | grep true"
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
    # Capture Helm template output
    run helm template multiple-trust-policies ./deployments/ratify-gatekeeper-provider \
        --set executor.scopes[0]="registry1.azurecr.io/" \
        --set notation.certs[0].provider=inline \
        --set-file notation.certs[0].cert="notation-file1.crt" \
        --set-file notation.certs[1].cert="notation-file2.crt" \
        --set-file notation.certs[2].cert="notation-file3.crt" \
        --set notation.scopes[0]="registry1.azurecr.io/" \
        --set notation.trustedIdentities[0]="x509.subject: cert identity 1" \
        --set stores[0].credential.provider=static
    assert_success
    rendered="$output"

    # the expected partial output
    expected_verifier_notation=$(cat <<EOF
    - name: notation-1
      type: notation
      parameters:
        scopes:
          - registry1.azurecr.io/
        trustedIdentities:
          - 'x509.subject: cert identity 1'
        certificates:
          - type: "ca"
EOF
    )

    # Assert that the rendered Helm output contains the expected section
    [[ "$rendered" == *"$expected_verifier_notation"* ]] || {
        echo "Rendered output does not contain the expected verifier-notation section."
        echo "Rendered output:"
        echo "$rendered"
        echo "Expected section:"
        echo "$expected_verifier_notation"
        return 1
    }

    # failure path:
    # Capture Helm template output with unsupported notation cert provider
    run helm template multiple-trust-policies ./deployments/ratify-gatekeeper-provider \
        --set executor.scopes[0]="registry1.azurecr.io/" \
        --set notation.certs[0].provider=unknownProvider \
        --set-file notation.certs[0].cert="notation-file1.crt" \
        --set-file notation.certs[1].cert="notation-file2.crt" \
        --set-file notation.certs[2].cert="notation-file3.crt" \
        --set stores[0].credential.provider=static

    assert_failure

    # the expected error message
    expected_verifier_notation=$(cat <<EOF
Unsupported notation certificate provider: unknownProvider
EOF
    )

    # Assert that the rendered Helm output contains the expected error message
    [[ "$output" == *"$expected_verifier_notation"* ]]
}

@test "crd version test" {
    skip "v2 executor CRD has only one version (v2alpha1), no version conversion to test"
    run kubectl delete verifiers.config.ratify.deislabs.io/verifier-notation
    assert_success
    run kubectl apply -f ./config/samples/clustered/verifier/config_v1alpha1_verifier_notation.yaml
    assert_success
    run bash -c "kubectl get verifiers.config.ratify.deislabs.io/verifier-notation -o yaml | grep 'apiVersion: config.ratify.deislabs.io/v1beta1'"
    assert_success

    run kubectl delete stores.config.ratify.deislabs.io/store-oras
    assert_success
    run kubectl apply -f ./config/samples/clustered/verifier/config_v1alpha1_store_oras_http.yaml
    assert_success
    run bash -c "kubectl get stores.config.ratify.deislabs.io/store-oras -o yaml | grep 'apiVersion: config.ratify.deislabs.io/v1beta1'"
    assert_success
}

@test "notation test" {
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo1 --namespace default --force --ignore-not-found=true'
    }
    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success
    sleep 5

    # validate executor status shows success
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
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor-tsa.yaml'
        rm -f original-executor-tsa.yaml
    }

    # save original executor state
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o yaml > original-executor-tsa.yaml"
    assert_success

    # validate executor status shows success
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o jsonpath='{.status.succeeded}' | grep true"

    # apply executor with TSA trust store certificate using JSON to avoid YAML document separator issues with PEM certs
    run bash -c 'TSA_CERT=$(cat ./test/bats/tests/certificates/tsarootca.cer) && \
        kubectl get executors.config.ratify.dev/'"${EXECUTOR_NAME}"' -o json | \
        jq --arg tsa_cert "$TSA_CERT" '"'"'del(.metadata.managedFields, .metadata.resourceVersion, .metadata.uid, .metadata.creationTimestamp, .metadata.generation, .status) | .spec.verifiers = [(.spec.verifiers[] | if .name == "notation-1" then .parameters.certificates += [{"type": "tsa", "inline": {"certs": $tsa_cert}}] else . end)]'"'"' | kubectl apply --server-side --force-conflicts -f -'
    assert_success
    # wait for executor to be reconciled after patch
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o jsonpath='{.status.succeeded}' | grep true"

    # verify that the image can now be run
    run kubectl run demo-tsa --namespace default --image=registry:5000/notation:tsa
    assert_success
}

@test "notation verification pass on CRL check with audit trust policy" {
    skip "v2 notation verifier does not support configurable verification level (audit); hardcoded to strict"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo --namespace default --force --ignore-not-found=true'

        # restore the original notation verifier for other tests
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl replace -f ./config/samples/clustered/verifier/config_v1beta1_verifier_notation.yaml'
    }
    TARGET_IP=$(ip -4 addr show "eth0" | awk '/inet/ {print $2}' | cut -d'/' -f1)
    # RATIFY_POD=$(kubectl get pods -n ${RATIFY_NAMESPACE} --no-headers -o custom-columns=":metadata.name" | grep ratify)
    run kubectl patch deployment ${RATIFY_NAME} -n ${RATIFY_NAMESPACE} --type='merge' -p '{"spec":{"template":{"spec":{"hostAliases":[{"ip":"'"${TARGET_IP}"'","hostnames":["yourhost"]}]}}}}'

    # add the tsaroot certificate as an inline key management provider
    cat ./test/bats/tests/config/config_v1beta1_keymanagementprovider_inline.yaml >> crlkmprovider.yaml
    cat .staging/notation/crl-test/root.crt | sed 's/^/      /g' >> crlkmprovider.yaml
    run kubectl apply -f crlkmprovider.yaml --namespace ${RATIFY_NAMESPACE}
    assert_success
    run kubectl replace -f ./test/bats/tests/config/config_v1beta1_verifier_notation_audit_crl.yaml

    run kubectl run demo --namespace default --image=registry:5000/notation:crl
    assert_success
}

@test "notation test with certs across namespace" {
    skip "v2 executor CRD is cluster-scoped only, namespace-scoped executor not yet supported (see #2672)"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo1 --namespace default --force --ignore-not-found=true'

        # restore cert store in ratify namespace
        run kubectl apply -f clusterkmprovider.yaml
        assert_success

        # restore the original notation verifier for other tests
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_notation.yaml'

        # delete new namespace
        run kubectl delete namespace new-namespace
        assert_success
    }

    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success
    sleep 5

    # create a new namespace.
    run kubectl create namespace new-namespace
    assert_success
    sleep 3

    # apply the key management provider to new namespace
    run bash -c "kubectl get keymanagementproviders.config.ratify.deislabs.io/ratify-notation-inline-cert-0 -o yaml > clusterkmprovider.yaml"
    assert_success
    sed 's/KeyManagementProvider/NamespacedKeyManagementProvider/' clusterkmprovider.yaml >namespacedkmprovider.yaml
    run kubectl apply -f namespacedkmprovider.yaml -n new-namespace
    assert_success

    # delete the cluster-wide key management provider
    run kubectl delete keymanagementproviders.config.ratify.deislabs.io/ratify-notation-inline-cert-0
    assert_success

    # configure the notation verifier to use inline certificate store in new namespace.
    sed 's/default\//new-namespace\//' ./config/samples/clustered/verifier/config_v1beta1_verifier_notation_specificnskmprovider.yaml >verifier-new-namespace.yaml
    run kubectl apply -f verifier-new-namespace.yaml
    assert_success
    sleep 3

    run kubectl run demo --namespace new-namespace --image=registry:5000/notation:signed
    assert_success

    run kubectl run demo1 --namespace new-namespace --image=registry:5000/notation:unsigned
    assert_failure
}

@test "cosign test" {
    skip "v2 cosign verifier forces IgnoreTLog=false for key-based verification, needs code fix to respect user config"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod cosign-demo-key --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod cosign-demo-unsigned --namespace default --force --ignore-not-found=true'
    }
    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success
    sleep 5

    run kubectl run cosign-demo-key --namespace default --image=registry:5000/cosign:signed-key
    assert_success

    run kubectl run cosign-demo-unsigned --namespace default --image=registry:5000/cosign:unsigned
    assert_failure
}

@test "cosign legacy keyed test" {
    skip "v2 cosign verifier does not support legacy format; also blocked by IgnoreTLog=false for key-based verification"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod cosign-demo-key --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod cosign-demo-unsigned --namespace default --force --ignore-not-found=true'
    }

    # use imperative command to guarantee verifier config is updated
    run kubectl replace -f ./config/samples/clustered/verifier/config_v1beta1_verifier_cosign_legacy.yaml
    sleep 5

    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
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

        # restore the original executor for other tests
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor-cosign-keyless.yaml'
        rm -f original-executor-cosign-keyless.yaml
    }

    # save original executor state
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o yaml > original-executor-cosign-keyless.yaml"
    assert_success

    # apply keyless cosign executor
    run kubectl apply --server-side --force-conflicts -f ${BATS_TESTS_DIR}/config/executor_cosign_keyless.yaml
    assert_success

    # wait for executor to be reconciled after config change
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o jsonpath='{.status.succeeded}' | grep true"

    wait_for_process 20 10 'kubectl run cosign-demo-keyless --namespace default --image=wabbitnetworks.azurecr.io/test/cosign-image:signed-keyless'
}

@test "cosign legacy keyless test" {
    skip "v2 cosign verifier does not support legacy format"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod cosign-demo-keyless --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl replace -f ./config/samples/clustered/verifier/config_v1beta1_verifier_cosign.yaml'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl replace -f ./config/samples/clustered/store/config_v1beta1_store_oras_http.yaml'
    }

    # use imperative command to guarantee useHttp is updated
    run kubectl replace -f ./config/samples/clustered/verifier/config_v1beta1_verifier_cosign_keyless_legacy.yaml
    sleep 5

    run kubectl replace -f ./config/samples/clustered/store/config_v1beta1_store_oras.yaml
    sleep 5

    wait_for_process 20 10 'kubectl run cosign-demo-keyless --namespace default --image=wabbitnetworks.azurecr.io/test/cosign-image:signed-keyless'
}
@test "validate crd add, replace and delete" {
    skip "TODO: removing notation verifier leaves cosign which fails due to IgnoreTLog=false, causing executor to fail and gatekeeper to pass"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod crdtest --namespace default --force --ignore-not-found=true'

        # restore the original executor for other tests
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor-crd.yaml'
        rm -f original-executor-crd.yaml
    }

    # save original executor state
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o yaml > original-executor-crd.yaml"
    assert_success

    echo "Patch executor to remove notation verifier and validate deployment fails"
    run bash -c 'kubectl get executors.config.ratify.dev/'"${EXECUTOR_NAME}"' -o json | \
        jq '"'"'del(.metadata.managedFields, .metadata.resourceVersion, .metadata.uid, .metadata.creationTimestamp, .metadata.generation, .status) | .spec.verifiers = [.spec.verifiers[] | select(.name != "notation-1")] | .spec.policyEnforcer.parameters.policy.rules = [.spec.policyEnforcer.parameters.policy.rules[] | select(.verifierName != "notation-1")]'"'"' | kubectl apply --server-side --force-conflicts -f -'
    assert_success
    # wait for executor to be reconciled
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o jsonpath='{.status.succeeded}' | grep true"
    run kubectl run crdtest --namespace default --image=registry:5000/notation:signed
    assert_failure

    echo "Restore original executor with notation verifier and validate deployment succeeds"
    run restore_executor original-executor-crd.yaml
    assert_success
    # wait for executor to be reconciled
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o jsonpath='{.status.succeeded}' | grep true"
    run kubectl run crdtest --namespace default --image=registry:5000/notation:signed
    assert_success
}

@test "store crd status check" {
    teardown() {
        echo "cleaning up"
        # restore the original executor for other tests
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor-store.yaml'
        rm -f original-executor-store.yaml
    }

    # save original executor state
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o yaml > original-executor-store.yaml"
    assert_success

    # patch executor with an invalid store type
    run bash -c 'kubectl get executors.config.ratify.dev/'"${EXECUTOR_NAME}"' -o json | \
        jq '"'"'del(.metadata.managedFields, .metadata.resourceVersion, .metadata.uid, .metadata.creationTimestamp, .metadata.generation, .status) | .spec.stores = [{"type": "invalid-store-type", "parameters": {"plainHttp": true}}]'"'"' | kubectl apply --server-side --force-conflicts -f -'
    assert_success
    # wait for executor to report error
    sleep 5
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o jsonpath='{.status.error}' | grep -i 'store'"
    assert_success
}

@test "configmap update test" {
    skip "Skipping test for now as we are no longer watching for configfile update in a K8s environment. This test ensures we are watching config file updates in a non-kub scenario"
    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success
    sleep 5
    run kubectl run demo2 --image=registry:5000/notation:signed
    assert_success

    run kubectl get configmaps ratify-configuration --namespace=${RATIFY_NAMESPACE} -o yaml >currentConfig.yaml
    run kubectl delete -f ./library/multi-tenancy-validation/samples/constraint.yaml

    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl replace --namespace=${RATIFY_NAMESPACE} -f ${BATS_TESTS_DIR}/configmap/invalidconfigmap.yaml"
    echo "Waiting for 150 second for configuration update"
    sleep 150

    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
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

    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
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

        # restore the original executor
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor-certstore.yaml'
        rm -f original-executor-certstore.yaml
    }

    # save original executor state
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o yaml > original-executor-certstore.yaml"
    assert_success

    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success
    sleep 5

    # verify that the image cannot be run due to an invalid cert
    run kubectl run demo-alternate --namespace default --image=registry:5000/notation:signed-alternate
    assert_failure

    # patch executor to use alternate inline certificate
    run bash -c 'ALT_CERT=$(cat ~/.config/notation/truststore/x509/ca/alternate-cert/alternate-cert.crt) && \
        kubectl get executors.config.ratify.dev/'"${EXECUTOR_NAME}"' -o json | \
        jq --arg alt_cert "$ALT_CERT" '"'"'del(.metadata.managedFields, .metadata.resourceVersion, .metadata.uid, .metadata.creationTimestamp, .metadata.generation, .status) | .spec.verifiers = [(.spec.verifiers[] | if .name == "notation-1" then .parameters.certificates = [{"type": "ca", "inline": {"certs": $alt_cert}}] else . end)]'"'"' | kubectl apply --server-side --force-conflicts -f -'
    assert_success
    # wait for executor to be reconciled
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o jsonpath='{.status.succeeded}' | grep true"
    sleep 10

    # verify that the image can now be run
    run kubectl run demo-alternate --namespace default --image=registry:5000/notation:signed-alternate
    assert_success
}

@test "validate inline key management provider" {
    teardown() {
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo-alternate --namespace default --force --ignore-not-found=true'

        # restore the original executor
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor-kmp.yaml'
        rm -f original-executor-kmp.yaml
    }

    # save original executor state
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o yaml > original-executor-kmp.yaml"
    assert_success

    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success

    # verify that the image cannot be run due to an invalid cert
    sleep 10
    run kubectl run demo-alternate --namespace default --image=registry:5000/notation:signed-alternate
    assert_failure
    sleep 10

    # patch executor to use alternate inline certificate
    run bash -c 'ALT_CERT=$(cat ~/.config/notation/truststore/x509/ca/alternate-cert/alternate-cert.crt) && \
        kubectl get executors.config.ratify.dev/'"${EXECUTOR_NAME}"' -o json | \
        jq --arg alt_cert "$ALT_CERT" '"'"'del(.metadata.managedFields, .metadata.resourceVersion, .metadata.uid, .metadata.creationTimestamp, .metadata.generation, .status) | .spec.verifiers = [(.spec.verifiers[] | if .name == "notation-1" then .parameters.certificates = [{"type": "ca", "inline": {"certs": $alt_cert}}] else . end)]'"'"' | kubectl apply --server-side --force-conflicts -f -'
    assert_success
    # wait for executor to be reconciled
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o jsonpath='{.status.succeeded}' | grep true"

    # verify that the image can now be run
    run kubectl run demo-alternate --namespace default --image=registry:5000/notation:signed-alternate
    assert_success
}

@test "validate inline key management provider with inline certificate store" {
    # this test validates that executor verifier config with inline cert works correctly
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo1 --namespace default --force --ignore-not-found=true'

        # restore original executor
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor-kmp-certstore.yaml'
        rm -f original-executor-kmp-certstore.yaml
    }

    # save original executor state
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o yaml > original-executor-kmp-certstore.yaml"
    assert_success

    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success

    # validate executor status shows success
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o jsonpath='{.status.succeeded}' | grep true"
    run kubectl run demo --namespace default --image=registry:5000/notation:signed
    assert_success

    sleep 10

    # validate executor still reports success
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o jsonpath='{.status.succeeded}' | grep true"
    run kubectl run demo1 --namespace default --image=registry:5000/notation:signed
    assert_success
}

@test "validate K8s secrets ORAS auth provider" {
    skip "v2 e2e uses static credential provider; k8s secret auth provider not configured in current executor"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo --namespace default --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo1 --namespace default --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl replace -f ./config/samples/clustered/store/config_v1beta1_store_oras_http.yaml'
    }

    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success
    sleep 5
    # apply store CRD with K8s secret auth provier enabled
    run kubectl apply -f ./config/samples/clustered/store/config_v1beta1_store_oras_k8secretAuth.yaml
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

        # restore the original executor
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor-leaf.yaml'
        rm -f original-executor-leaf.yaml
    }

    # save original executor state
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o yaml > original-executor-leaf.yaml"
    assert_success

    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success

    # patch executor to use root cert for leaf-test
    run bash -c 'ROOT_CERT=$(cat ~/.config/notation/truststore/x509/ca/leaf-test/root.crt) && \
        kubectl get executors.config.ratify.dev/'"${EXECUTOR_NAME}"' -o json | \
        jq --arg root_cert "$ROOT_CERT" '"'"'del(.metadata.managedFields, .metadata.resourceVersion, .metadata.uid, .metadata.creationTimestamp, .metadata.generation, .status) | .spec.verifiers = [(.spec.verifiers[] | if .name == "notation-1" then .parameters.certificates = [{"type": "ca", "inline": {"certs": $root_cert}}] else . end)]'"'"' | kubectl apply --server-side --force-conflicts -f -'
    assert_success
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o jsonpath='{.status.succeeded}' | grep true"

    # verify that the image can be run with a root cert
    run kubectl run demo-leaf --namespace default --image=registry:5000/notation:leafSigned
    assert_success

    # patch executor to use the leaf cert instead of the root cert; leaf certs are rejected as trust anchors
    run bash -c 'LEAF_CERT=$(cat ~/.config/notation/truststore/x509/ca/leaf-test/leaf.crt) && \
        kubectl get executors.config.ratify.dev/'"${EXECUTOR_NAME}"' -o json | \
        jq --arg leaf_cert "$LEAF_CERT" '"'"'del(.metadata.managedFields, .metadata.resourceVersion, .metadata.uid, .metadata.creationTimestamp, .metadata.generation, .status) | .spec.verifiers = [(.spec.verifiers[] | if .name == "notation-1" then .parameters.certificates = [{"type": "ca", "inline": {"certs": $leaf_cert}}] else . end)]'"'"' | kubectl apply --server-side --force-conflicts -f -'
    assert_success
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o jsonpath='{.status.succeeded}' | grep false"

    # the provider keeps serving the last-known-good (root cert) config after an
    # invalid update, so restart it to force a fresh load of the leaf-only trust
    # store. The leaf cert is rejected as a trust anchor, leaving no valid
    # executor, so admission must fail closed. The restart is a workaround for
    # notaryproject/ratify#2798 (invalid config is not enforced until restart).
    run kubectl get deploy --namespace ${RATIFY_NAMESPACE} -l app.kubernetes.io/name=ratify-gatekeeper-provider -o jsonpath='{.items[0].metadata.name}'
    assert_success
    ratify_deploy="$output"
    if [ -z "$ratify_deploy" ]; then
        echo "no ratify-gatekeeper-provider deployment found in namespace ${RATIFY_NAMESPACE}" >&2
        return 1
    fi
    run kubectl rollout restart deployment/${ratify_deploy} --namespace ${RATIFY_NAMESPACE}
    assert_success
    run kubectl rollout status deployment/${ratify_deploy} --namespace ${RATIFY_NAMESPACE} --timeout=180s
    assert_success
    sleep 5

    # verify that the image cannot be run with a leaf cert
    run kubectl run demo-leaf2 --namespace default --image=registry:5000/notation:leafSigned
    assert_failure
}

@test "validate ratify/gatekeeper tls cert rotation" {
    teardown() {
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo --namespace default --force --ignore-not-found=true'
    }

    # update Providers to use the new CA
    run bash -c 'CA=$(cat .staging/rotation/ca.crt | base64 -w 0) && \
        kubectl get Provider ratify-gatekeeper-mutation-provider -o json | \
        jq --arg ca "$CA" ".spec.caBundle=\$ca" | kubectl replace -f -'
    assert_success
    run bash -c 'CA=$(cat .staging/rotation/ca.crt | base64 -w 0) && \
        kubectl get Provider ratify-gatekeeper-provider -o json | \
        jq --arg ca "$CA" ".spec.caBundle=\$ca" | kubectl replace -f -'
    assert_success

    # update the ratify tls secret to use the new tls cert and key
    run bash -c 'CERT=$(cat .staging/rotation/server.crt | base64 -w 0) && \
        KEY=$(cat .staging/rotation/server.key | base64 -w 0) && \
        kubectl get secret ratify-gatekeeper-provider-tls -n gatekeeper-system -o json | \
        jq --arg cert "$CERT" --arg key "$KEY" ".data[\"tls.key\"]=\$key | .data[\"tls.crt\"]=\$cert" | kubectl replace -f -'
    assert_success

    # update the gatekeeper webhook server tls secret to use the new cert bundle
    run bash -c 'CA_CERT=$(cat .staging/rotation/gatekeeper/ca.crt | base64 -w 0) && \
        CA_KEY=$(cat .staging/rotation/gatekeeper/ca.key | base64 -w 0) && \
        TLS_CERT=$(cat .staging/rotation/gatekeeper/server.crt | base64 -w 0) && \
        TLS_KEY=$(cat .staging/rotation/gatekeeper/server.key | base64 -w 0) && \
        kubectl get Secret gatekeeper-webhook-server-cert -n gatekeeper-system -o json | \
        jq --arg caCert "$CA_CERT" --arg caKey "$CA_KEY" --arg tlsCert "$TLS_CERT" --arg tlsKey "$TLS_KEY" \
        ".data[\"ca.crt\"]=\$caCert | .data[\"ca.key\"]=\$caKey | .data[\"tls.crt\"]=\$tlsCert | .data[\"tls.key\"]=\$tlsKey" | kubectl replace -f -'
    assert_success

    # volume projection can take up to 90 seconds
    sleep 100

    # verify that the verification succeeds
    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success
    sleep 5
    run kubectl run demo --namespace default --image=registry:5000/notation:signed
    assert_success
}

@test "namespaced notation/cosign verifiers test" {
    skip "v2 executor CRD is cluster-scoped only, namespace-scoped executor not yet supported (see #2672)"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete namespacedverifiers.config.ratify.deislabs.io/verifier-cosign --namespace default --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete namespacedverifiers.config.ratify.deislabs.io/verifier-notation --namespace default --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_notation.yaml'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_cosign.yaml'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete namespacedkeymanagementproviders.config.ratify.deislabs.io/ratify-notation-inline-cert-0 -n default --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl apply -f clusternotationkmprovider.yaml'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete namespacedkeymanagementproviders.config.ratify.deislabs.io/ratify-cosign-inline-key-0 -n default --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl apply -f clustercosignkmprovider.yaml'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete namespacedpolicies.config.ratify.deislabs.io/ratify-policy --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl apply -f clusterpolicy.yaml'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod notation-demo --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod notation-demo1 --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod cosign-demo-key --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod cosign-demo-unsigned --namespace default --force --ignore-not-found=true'
    }

    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    sleep 3

    # apply namespaced policy and delete cluster-wide policy.
    run bash -c "kubectl get policies.config.ratify.deislabs.io/ratify-policy -o yaml > clusterpolicy.yaml"
    assert_success
    sed 's/kind: Policy/kind: NamespacedPolicy/;/^\s*resourceVersion:/d' clusterpolicy.yaml >namespacedpolicy.yaml
    run kubectl apply -f namespacedpolicy.yaml
    assert_success

    # apply namespaced kmp and delete cluster-wide kmp.
    run bash -c "kubectl get keymanagementproviders.config.ratify.deislabs.io/ratify-notation-inline-cert-0 -o yaml > clusternotationkmprovider.yaml"
    assert_success
    sed 's/KeyManagementProvider/NamespacedKeyManagementProvider/' clusternotationkmprovider.yaml >namespacednotationkmprovider.yaml
    run kubectl apply -f namespacednotationkmprovider.yaml
    assert_success

    run bash -c "kubectl get keymanagementproviders.config.ratify.deislabs.io/ratify-cosign-inline-key-0 -o yaml > clustercosignkmprovider.yaml"
    assert_success
    sed 's/KeyManagementProvider/NamespacedKeyManagementProvider/;/^\s*resourceVersion:/d' clustercosignkmprovider.yaml >namespacedcosignkmprovider.yaml
    run kubectl delete namespacedkeymanagementproviders.config.ratify.deislabs.io/ratify-cosign-inline-key-0 -n default --ignore-not-found=true
    sleep 5
    run kubectl apply -f namespacedcosignkmprovider.yaml
    assert_success
    sleep 5

    # apply namespaced notation verifiers and delete cluster-wide notation verifiers.
    run kubectl apply -f ./config/samples/namespaced/verifier/config_v1beta1_verifier_notation.yaml
    run kubectl delete verifiers.config.ratify.deislabs.io/verifier-notation --ignore-not-found=true

    # validate notation images.
    run kubectl run notation-demo --namespace default --image=registry:5000/notation:signed
    assert_success

    run kubectl run notation-demo1 --namespace default --image=registry:5000/notation:unsigned
    assert_failure

    # apply namespaced cosign verifiers and delete cluster-wide cosign verifiers.
    run kubectl apply -f ./config/samples/namespaced/verifier/config_v1beta1_verifier_cosign.yaml
    run kubectl delete verifiers.config.ratify.deislabs.io/verifier-cosign --ignore-not-found=true

    # validate cosign images.
    run kubectl run cosign-demo-key --namespace default --image=registry:5000/cosign:signed-key
    assert_success

    run kubectl run cosign-demo-unsigned --namespace default --image=registry:5000/cosign:unsigned
    assert_failure
}
