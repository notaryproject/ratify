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

@test "dynamic plugins enabled test" {
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
    teardown() {
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete keymanagementproviders.config.ratify.deislabs.io/keymanagementprovider-inline --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo-leaf --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo-leaf2 --namespace default --force --ignore-not-found=true'

        # restore the original notation verifier for other tests
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl apply -f ./test/bats/tests/config/config_v1beta1_verifier_notation_akv.yaml'
    }

    # configure the default template/constraint
    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success

    # verify that the image can be run with a root cert, root verification cert should have been configured on deployment
    wait_for_process 20 10 'kubectl run demo-leaf --namespace default --image=${TEST_REGISTRY}/notation:leafSigned'
    assert_success

    # add the leaf certificate as an inline certificate store
    cat ~/.config/notation/truststore/x509/ca/leaf-test/leaf.crt | sed 's/^/      /g' >>./test/bats/tests/config/config_v1beta1_keymanagementprovider_inline.yaml
    run kubectl apply -f ./test/bats/tests/config/config_v1beta1_keymanagementprovider_inline.yaml
    assert_success
    sed -i '10,$d' ./test/bats/tests/config/config_v1beta1_keymanagementprovider_inline.yaml

    # configure the notation verifier to use the inline key management provider
    run kubectl apply -f ./test/bats/tests/config/config_v1beta1_verifier_notation_kmprovider.yaml
    assert_success

    # wait for the httpserver cache to be invalidated
    sleep 15
    # verify that the image cannot be run with a leaf cert
    run kubectl run demo-leaf2 --namespace default --image=${TEST_REGISTRY}/notation:leafSigned
    assert_failure
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
    wait_for_process 20 10 'kubectl run demo --namespace default --image=${TEST_REGISTRY}/notation:signed'
    assert_success
    run kubectl run demo1 --namespace default --image=${TEST_REGISTRY}/notation:unsigned
    assert_failure
}

@test "cosign test" {
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
    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success
    sleep 5
    wait_for_process 20 10 'kubectl run mutate-demo --namespace default --image=${TEST_REGISTRY}/notation:signed'
    assert_success
    result=$(kubectl get pod mutate-demo --namespace default -o json | jq -r ".spec.containers[0].image" | grep @sha)
    assert_mutate_success
}

@test "validate refresher reconcile count" {
    sed -i -e "s/keymanagementprovider-akv/kmp-akv-refresh/" \
        -e "s/1m/1s/" \
        -e "s/yourCertName/${NOTATION_PEM_NAME}/" \
        -e '/version: yourCertVersion/d' \
        -e "s|https://yourkeyvault.vault.azure.net/|${VAULT_URI}|" \
        -e "s/tenantID:/tenantID: ${TENANT_ID}/" \
        -e "s/clientID:/clientID: ${IDENTITY_CLIENT_ID}/" \
        ./config/samples/clustered/kmp/config_v1beta1_keymanagementprovider_akv_refresh_enabled.yaml
    run kubectl apply -f ./config/samples/clustered/kmp/config_v1beta1_keymanagementprovider_akv_refresh_enabled.yaml
    assert_success
    sleep 10
    count=$(kubectl logs deployment/ratify -n gatekeeper-system | grep "Reconciled KeyManagementProvider" | wc -l)
    [ $count -ge 4 ]
}

@test "validate certificate version update" {
    result=$(kubectl get keymanagementprovider kmp-akv-refresh -o jsonpath='{.status.properties.Certificates[0].Version}')
    az keyvault certificate get-default-policy -o json >>policy.json
    wait_for_process 20 10 "az keyvault certificate create --vault-name $KEYVAULT_NAME --name $NOTATION_PEM_NAME --policy @policy.json"
    sleep 15
    run rm policy.json
    refreshResult=$(kubectl get keymanagementprovider kmp-akv-refresh -o jsonpath='{.status.properties.Certificates[0].Version}')
    [ "$result" != "$refreshResult" ]
}

@test "validate certificate specified version" {
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete keymanagementprovider kmp-akv-refresh --ignore-not-found=true'
        rm policy.json
    }
    version=$(az keyvault certificate show --vault-name $KEYVAULT_NAME --name $NOTATION_PEM_NAME --query 'sid' -o tsv | rev | cut -d'/' -f1 | rev)
    sed -i "/- name: default/a\ \ \ \     version: ${version}" ./config/samples/clustered/kmp/config_v1beta1_keymanagementprovider_akv_refresh_enabled.yaml
    run kubectl apply -f ./config/samples/clustered/kmp/config_v1beta1_keymanagementprovider_akv_refresh_enabled.yaml
    assert_success
    result=$(kubectl get keymanagementprovider kmp-akv-refresh -o jsonpath='{.status.properties.Certificates[0].Version}')
    az keyvault certificate get-default-policy -o json >>policy.json
    wait_for_process 20 10 "az keyvault certificate create --vault-name $KEYVAULT_NAME --name $NOTATION_PEM_NAME --policy @policy.json"
    sleep 15
    refreshResult=$(kubectl get keymanagementprovider kmp-akv-refresh -o jsonpath='{.status.properties.Certificates[0].Version}')
    [ "$result" = "$refreshResult" ]
}
