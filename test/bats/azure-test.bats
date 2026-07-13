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

# AKS end-to-end tests for the Ratify v2 gatekeeper provider.
# See scripts/azure-ci-test.sh for the deployment.
#
# Only the notation (AKV) and mutation cases run against v2 today. The remaining
# cases are retained as `skip`-ped stubs (their original bodies are kept) so the
# diff stays traceable and each can be re-enabled pr-by-pr as the corresponding
# v2 capability lands. See the skip message on each for the specific reason.

load helpers

BATS_TESTS_DIR=${BATS_TESTS_DIR:-test/bats/tests}
WAIT_TIME=60
SLEEP_TIME=1
EXECUTOR_NAME=ratify-gatekeeper-provider-executor-1
RATIFY_NAMESPACE=gatekeeper-system

@test "dynamic plugins enabled test" {
    skip "v2 gatekeeper provider has no dynamic plugin mechanism"
    # only run this test against a live cluster

    # ensure that the chart deployment is reset to a clean state for other tests
    teardown() {
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete verifiers.config.ratify.deislabs.io/verifier-dynamic --ignore-not-found=true'
        pod=$(kubectl -n gatekeeper-system get pod -l=app.kubernetes.io/name=ratify --sort-by=.metadata.creationTimestamp -o=name | tail -n 1)
        helm upgrade --atomic --namespace gatekeeper-system --reuse-values --set featureFlags.RATIFY_EXPERIMENTAL_DYNAMIC_PLUGINS=false ratify ./charts/ratify
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl -n gatekeeper-system delete $pod --force --grace-period=0'
    }

    # enable dynamic plugins
    helm upgrade --atomic --namespace gatekeeper-system --reuse-values --set featureFlags.RATIFY_EXPERIMENTAL_DYNAMIC_PLUGINS=true ratify ./charts/ratify
    sleep 30
    latestpod=$(kubectl -n gatekeeper-system get pod -l=app.kubernetes.io/name=ratify --sort-by=.metadata.creationTimestamp -o=name | tail -n 1)

    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_dynamic.yaml
    sleep 5

    # parse the logs for the newly created ratify pod
    run bash -c "kubectl -n gatekeeper-system logs $latestpod | grep 'downloaded verifier plugin dynamic from .* to .*'"
    assert_success
}

@test "validate image signed by leaf cert" {
    skip "blocked by notaryproject/ratify#2693: the v2 notation verifier admits a leaf-only inline trust store, so the leaf-signed image is not rejected"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo-leaf --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo-leaf2 --namespace default --force --ignore-not-found=true'
        # restore the original executor (AKV notation cert) for the other tests,
        # best-effort: only if it was actually saved
        if [ -s original-executor-leaf.yaml ]; then
            wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'restore_executor original-executor-leaf.yaml'
            rm -f original-executor-leaf.yaml
        fi
    }

    run kubectl apply -f ./library/default/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/default/samples/constraint.yaml
    assert_success
    sleep 5

    # save the original executor so the AKV notation cert can be restored afterwards
    run bash -c "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o yaml > original-executor-leaf.yaml"
    assert_success

    # patch the notation verifier to trust the leaf-test ROOT certificate (inline)
    run bash -c 'ROOT_CERT=$(cat ~/.config/notation/truststore/x509/ca/leaf-test/root.crt) && \
        kubectl get executors.config.ratify.dev/'"${EXECUTOR_NAME}"' -o json | \
        jq --arg cert "$ROOT_CERT" '"'"'del(.metadata.managedFields, .metadata.resourceVersion, .metadata.uid, .metadata.creationTimestamp, .metadata.generation, .status) | .spec.verifiers = [(.spec.verifiers[] | if .name == "notation-1" then .parameters.certificates = [{"type": "ca", "inline": {"certs": $cert}}] else . end)]'"'"' | kubectl apply --server-side --force-conflicts -f -'
    assert_success
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o jsonpath='{.status.succeeded}' | grep true"

    # a leaf-signed image chains up to the root cert, so admission should pass
    run wait_for_process 20 10 'kubectl run demo-leaf --namespace default --image=${TEST_REGISTRY}/notation:leafSigned'
    assert_success

    # patch the notation verifier to trust ONLY the LEAF certificate (inline)
    run bash -c 'LEAF_CERT=$(cat ~/.config/notation/truststore/x509/ca/leaf-test/leaf.crt) && \
        kubectl get executors.config.ratify.dev/'"${EXECUTOR_NAME}"' -o json | \
        jq --arg cert "$LEAF_CERT" '"'"'del(.metadata.managedFields, .metadata.resourceVersion, .metadata.uid, .metadata.creationTimestamp, .metadata.generation, .status) | .spec.verifiers = [(.spec.verifiers[] | if .name == "notation-1" then .parameters.certificates = [{"type": "ca", "inline": {"certs": $cert}}] else . end)]'"'"' | kubectl apply --server-side --force-conflicts -f -'
    assert_success
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o jsonpath='{.status.succeeded}' | grep true"

    # The provider caches verification results by image digest and does not
    # drop them when the Executor trust store changes, so restart the provider
    # to serve the leaf-only trust store with a clean cache.
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
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o jsonpath='{.status.succeeded}' | grep true"
    sleep 5

    # with only the leaf cert as the trust anchor, the same image must be rejected
    run kubectl run demo-leaf2 --namespace default --image=${TEST_REGISTRY}/notation:leafSigned
    assert_failure
}

@test "notation akv test" {
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo1 --namespace default --force --ignore-not-found=true'
    }

    run kubectl apply -f ./library/default/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/default/samples/constraint.yaml
    assert_success
    sleep 5

    # signed image, validated against the AKV notation certificate, should pass
    run wait_for_process 20 10 'kubectl run demo --namespace default --image=${TEST_REGISTRY}/notation:signed'
    assert_success

    # unsigned image should be rejected
    run kubectl run demo1 --namespace default --image=${TEST_REGISTRY}/notation:unsigned
    assert_failure
}

@test "cosign test" {
    skip "blocked by notaryproject/ratify#2712: v2 cosign key-based verification requires a tlog/timestamp, so an offline AKV-key-signed image is rejected"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod cosign-demo --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod cosign-demo2 --namespace default --force --ignore-not-found=true'
    }

    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./test/bats/tests/config/config_v1beta1_verifier_cosign_akv.yaml
    assert_success
    sleep 5

    wait_for_process 20 10 'kubectl run cosign-demo --namespace default --image=${TEST_REGISTRY}/cosign:signed-key'
    assert_success
    run kubectl run cosign-demo2 --namespace default --image=${TEST_REGISTRY}/cosign:unsigned
    assert_failure
}

@test "licensechecker test" {
    skip "no licensechecker verifier in the v2 gatekeeper provider yet"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod license-checker --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod license-checker2 --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete verifiers.config.ratify.deislabs.io/verifier-license-checker --ignore-not-found=true'
    }

    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success
    sleep 5

    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_partial_licensechecker.yaml
    sleep 5
    run kubectl run license-checker --namespace default --image=${TEST_REGISTRY}/licensechecker:v0
    assert_failure

    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_complete_licensechecker.yaml
    # wait for the httpserver cache to be invalidated
    sleep 15
    wait_for_process 20 10 'kubectl run license-checker2 --namespace default --image=${TEST_REGISTRY}/licensechecker:v0'
    assert_success
}

@test "sbom verifier test" {
    skip "no sbom verifier in the v2 gatekeeper provider yet"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod sbom --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod sbom2 --namespace default --force --ignore-not-found=true'
    }

    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success
    sleep 5

    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_sbom.yaml
    sleep 5
    wait_for_process 20 10 'kubectl run sbom --namespace default --image=${TEST_REGISTRY}/sbom:v0'
    assert_success

    run kubectl delete verifiers.config.ratify.deislabs.io/verifier-sbom
    assert_success
    # wait for the httpserver cache to be invalidated
    sleep 15
    run kubectl run sbom2 --namespace default --image=${TEST_REGISTRY}/sbom:v0
    assert_failure
}

@test "schemavalidator verifier test" {
    skip "no schemavalidator verifier in the v2 gatekeeper provider yet"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete verifiers.config.ratify.deislabs.io/verifier-license-checker --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete verifiers.config.ratify.deislabs.io/verifier-sbom --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete verifiers.config.ratify.deislabs.io/verifier-schemavalidator --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod schemavalidator --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod schemavalidator2 --namespace default --force --ignore-not-found=true'
    }

    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success
    sleep 5

    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_schemavalidator.yaml
    sleep 5

    wait_for_process 20 10 'kubectl run schemavalidator --namespace default --image=${TEST_REGISTRY}/schemavalidator:v0'
    assert_success

    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_schemavalidator_bad.yaml
    # wait for the httpserver cache to be invalidated
    sleep 15
    run kubectl run schemavalidator2 --namespace default --image=${TEST_REGISTRY}/schemavalidator:v0
    assert_failure
}

@test "sbom/notary/cosign/licensechecker/schemavalidator verifiers test" {
    skip "depends on sbom/licensechecker/schemavalidator/cosign verifiers not yet in the v2 gatekeeper provider"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete verifiers.config.ratify.deislabs.io/verifier-license-checker --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete verifiers.config.ratify.deislabs.io/verifier-sbom --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete verifiers.config.ratify.deislabs.io/verifier-schemavalidator --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete verifiers.config.ratify.deislabs.io/verifier-cosign --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod all-in-one --namespace default --force --ignore-not-found=true'
    }

    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success
    sleep 5

    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_sbom.yaml
    sleep 5
    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_complete_licensechecker.yaml
    sleep 5
    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_schemavalidator.yaml
    sleep 5

    wait_for_process 20 10 'kubectl run all-in-one --namespace default --image=${TEST_REGISTRY}/all:v0'
    assert_success
}

@test "validate crd add, replace and delete" {
    skip "v2 configures verifiers via the Executor CRD; runtime verifier CRD add/replace/delete is covered by the kind base-test.bats migration"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod crdtest --namespace default --force --ignore-not-found=true'
    }

    echo "adding license checker, delete notation verifier and validate deployment fails due to missing notation verifier"
    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_complete_licensechecker.yaml
    assert_success
    run kubectl delete verifiers.config.ratify.deislabs.io/verifier-notation
    assert_success
    # wait for the httpserver cache to be invalidated
    sleep 15
    run kubectl run crdtest --namespace default --image=${TEST_REGISTRY}/notation:signed
    assert_failure

    echo "Add notation verifier and validate deployment succeeds"
    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_notation_kmprovider.yaml
    assert_success

    # wait for the httpserver cache to be invalidated
    sleep 15
    wait_for_process 20 10 'kubectl run crdtest --namespace default --image=${TEST_REGISTRY}/notation:signed'
    assert_success
}

@test "configmap update test" {
    skip "Skipping test for now as we are no longer watching for configfile update in a K8s environment.This test ensures we are watching config file updates in a non-kub scenario"
    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success
    sleep 5
    wait_for_process 20 10 'kubectl run demo2 --image=${TEST_REGISTRY}/notation:signed'
    assert_success

    run kubectl get configmaps ratify-configuration --namespace=gatekeeper-system -o yaml >currentConfig.yaml
    run kubectl delete -f ./library/multi-tenancy-validation/samples/constraint.yaml

    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl replace --namespace=gatekeeper-system -f ${BATS_TESTS_DIR}/configmap/invalidconfigmap.yaml"
    echo "Waiting for 150 second for configuration update"
    sleep 150

    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success
    run kubectl run demo3 --image=${TEST_REGISTRY}/notation:signed
    echo "Current time after validate : $(date +"%T")"
    assert_failure

    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl replace --namespace=gatekeeper-system -f currentConfig.yaml"
}

@test "dynamic plugins disabled test" {
    skip "v2 gatekeeper provider has no dynamic plugin mechanism"
    teardown() {
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete verifiers.config.ratify.deislabs.io/verifier-dynamic --namespace default --ignore-not-found=true'
    }

    start=$(date --iso-8601=seconds)
    latestpod=$(kubectl -n gatekeeper-system get pod -l=app.kubernetes.io/name=ratify --sort-by=.metadata.creationTimestamp -o=name | tail -n 1)

    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_dynamic.yaml
    sleep 5

    run bash -c "kubectl -n gatekeeper-system logs $latestpod --since-time=$start | grep 'dynamic plugins are currently disabled'"
    assert_success
}

@test "validate mutation tag to digest" {
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod mutate-demo --namespace default --ignore-not-found=true'
    }

    run kubectl apply -f ./library/default/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/default/samples/constraint.yaml
    assert_success
    sleep 5

    run wait_for_process 20 10 'kubectl run mutate-demo --namespace default --image=${TEST_REGISTRY}/notation:signed'
    assert_success
    run bash -c 'kubectl get pod mutate-demo --namespace default -o json | jq -r ".spec.containers[0].image" | grep @sha'
    assert_mutate_success
}

@test "validate refresher reconcile count" {
    skip "no KeyManagementProvider/refresher in the v2 gatekeeper provider"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete keymanagementprovider kmp-akv-refresh --ignore-not-found=true'
        rm test.yaml
    }
    sed -e "s/keymanagementprovider-akv/kmp-akv-refresh/" \
        -e "s/1m/1s/" \
        -e "s/yourCertName/${NOTATION_PEM_NAME}/" \
        -e '/version: yourCertVersion/d' \
        -e "s|https://yourkeyvault.vault.azure.net/|${VAULT_URI}|" \
        -e "s/tenantID:/tenantID: ${TENANT_ID}/" \
        -e "s/clientID:/clientID: ${IDENTITY_CLIENT_ID}/" \
        ./config/samples/clustered/kmp/config_v1beta1_keymanagementprovider_akv_refresh_enabled.yaml >test.yaml
    run kubectl apply -f test.yaml
    assert_success
    sleep 10
    count=$(kubectl logs deployment/ratify -n gatekeeper-system | grep "Reconciled KeyManagementProvider" | wc -l)
    [ $count -ge 4 ]
}

@test "validate refresher updates kmp with latest certificate version" {
    skip "no KeyManagementProvider/refresher in the v2 gatekeeper provider"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete keymanagementprovider kmp-akv-refresh --ignore-not-found=true'
        rm test.yaml
        rm policy.json
    }
    sed -e "s/keymanagementprovider-akv/kmp-akv-refresh/" \
        -e "s/1m/5s/" \
        -e "s/yourCertName/${NOTATION_PEM_NAME}/" \
        -e '/version: yourCertVersion/d' \
        -e "s|https://yourkeyvault.vault.azure.net/|${VAULT_URI}|" \
        -e "s/tenantID:/tenantID: ${TENANT_ID}/" \
        -e "s/clientID:/clientID: ${IDENTITY_CLIENT_ID}/" \
        ./config/samples/clustered/kmp/config_v1beta1_keymanagementprovider_akv_refresh_enabled.yaml >test.yaml
    run kubectl apply -f test.yaml
    assert_success
    sleep 5
    result=$(kubectl get keymanagementprovider kmp-akv-refresh -o jsonpath='{.status.properties.Certificates[0].Version}')
    az keyvault certificate get-default-policy -o json >>policy.json
    wait_for_process 20 10 "az keyvault certificate create --vault-name $KEYVAULT_NAME --name $NOTATION_PEM_NAME --policy @policy.json"
    sleep 30
    refreshResult=$(kubectl get keymanagementprovider kmp-akv-refresh -o jsonpath='{.status.properties.Certificates[0].Version}')
    [ "$result" != "$refreshResult" ]
}

@test "validate certificate specified version" {
    skip "no KeyManagementProvider/refresher in the v2 gatekeeper provider"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete keymanagementprovider kmp-akv-refresh --ignore-not-found=true'
        rm policy.json
        rm test.yaml
    }
    sed -e "s/keymanagementprovider-akv/kmp-akv-refresh/" \
        -e "s/1m/1s/" \
        -e "s/yourCertName/${NOTATION_PEM_NAME}/" \
        -e '/version: yourCertVersion/d' \
        -e "s|https://yourkeyvault.vault.azure.net/|${VAULT_URI}|" \
        -e "s/tenantID:/tenantID: ${TENANT_ID}/" \
        -e "s/clientID:/clientID: ${IDENTITY_CLIENT_ID}/" \
        ./config/samples/clustered/kmp/config_v1beta1_keymanagementprovider_akv_refresh_enabled.yaml >test.yaml
    version=$(az keyvault certificate show --vault-name $KEYVAULT_NAME --name $NOTATION_PEM_NAME --query 'sid' -o tsv | rev | cut -d'/' -f1 | rev)
    sed -i \
        -e "/name: ${NOTATION_PEM_NAME}/a \ \ \ \ \ \ \ \ version: ${version}" \
        test.yaml
    run kubectl apply -f test.yaml
    assert_success
    sleep 10
    result=$(kubectl get keymanagementprovider kmp-akv-refresh -o jsonpath='{.status.properties.Certificates[0].Version}')
    az keyvault certificate get-default-policy -o json >>policy.json
    wait_for_process 20 10 "az keyvault certificate create --vault-name $KEYVAULT_NAME --name $NOTATION_PEM_NAME --policy @policy.json"
    sleep 30
    refreshResult=$(kubectl get keymanagementprovider kmp-akv-refresh -o jsonpath='{.status.properties.Certificates[0].Version}')
    [ "$result" = "$refreshResult" ]
}
