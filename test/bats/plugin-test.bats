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

@test "helm genCert test" {
    skip "TODO: migrate to v2 executor CRD"
    # tls cert provided
    helm uninstall ratify --namespace gatekeeper-system
    make e2e-helm-deploy-ratify CERT_DIR=${CERT_DIR} CERT_ROTATION_ENABLED=true GATEKEEPER_VERSION=${GATEKEEPER_VERSION}
    sleep 5

    providedCert=$(cat ${CERT_DIR}/server.crt | base64 | tr -d '\n')
    generatedCert=$(kubectl -n gatekeeper-system get Secret ratify-tls -o jsonpath="{.data.tls\\.crt}")
    run [ "$generatedCert" == "$providedCert" ]
    assert_success

    # tls certs not provided, ratify-tls Secret exists and cert-rotation disabled
    helm uninstall ratify --namespace gatekeeper-system
    make e2e-helm-deploy-ratify-without-tls-certs CERT_ROTATION_ENABLED=false GATEKEEPER_VERSION=${GATEKEEPER_VERSION}
    sleep 5

    generatedCert=$(kubectl -n gatekeeper-system get Secret ratify-tls -o jsonpath="{.data.tls\\.crt}")
    run [ "$generatedCert" == "$providedCert" ]
    assert_success

    # tls certs not provided, ratify-tls Secret deleted and cert-rotation enabled
    helm uninstall ratify --namespace gatekeeper-system
    run kubectl delete --namespace gatekeeper-system secret ratify-tls
    assert_success
    make e2e-helm-deploy-ratify-without-tls-certs CERT_ROTATION_ENABLED=true GATEKEEPER_VERSION=${GATEKEEPER_VERSION}
    sleep 5

    ratifyPod=$(kubectl -n gatekeeper-system get pod -l=app.kubernetes.io/name=ratify --sort-by=.metadata.creationTimestamp -o=name | tail -n 1)
    run bash -c "kubectl -n gatekeeper-system logs $ratifyPod | grep 'refreshing CA and server certs'"
    assert_success
}

@test "cert rotator test" {
    skip "TODO: migrate to v2 executor CRD"
    helm uninstall ratify --namespace gatekeeper-system
    make e2e-helm-deploy-ratify CERT_DIR=${EXPIRING_CERT_DIR} CERT_ROTATION_ENABLED=true GATEKEEPER_VERSION=${GATEKEEPER_VERSION}
    sleep 10
    run [ "$(kubectl get secret ratify-tls -n gatekeeper-system -o json | jq '.data."ca.crt"')" != "$(cat ${EXPIRING_CERT_DIR}/ca.crt | base64 | tr -d '\n')" ]
    assert_success
}

@test "licensechecker test" {
    skip "TODO: migrate to v2 executor CRD"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod license-checker --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod license-checker2 --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete verifiers.config.ratify.deislabs.io/verifier-license-checker --namespace default --ignore-not-found=true'
    }

    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_partial_licensechecker.yaml
    sleep 5
    run kubectl run license-checker --namespace default --image=registry:5000/licensechecker:v0
    assert_failure

    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_complete_licensechecker.yaml
    # wait for the httpserver cache to be invalidated
    sleep 15
    run kubectl run license-checker2 --namespace default --image=registry:5000/licensechecker:v0
    assert_success
}

@test "sbom verifier test" {
    skip "TODO: migrate to v2 executor CRD"
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

    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_sbom_deny.yaml
    sleep 5
    run kubectl run sbom --namespace default --image=registry:5000/sbom:v0
    assert_failure

    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_sbom.yaml
    # wait for the httpserver cache to be invalidated
    sleep 15
    run kubectl run sbom --namespace default --image=registry:5000/sbom:v0
    assert_success

    run kubectl delete verifiers.config.ratify.deislabs.io/verifier-sbom
    assert_success
    # wait for the httpserver cache to be invalidated
    sleep 15
    run kubectl run sbom2 --namespace default --image=registry:5000/sbom:v0
    assert_failure
}

@test "schemavalidator verifier test" {
    skip "Skipping test for now until expected usage/configuration of this plugin can be verified"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete verifiers.config.ratify.deislabs.io/verifier-license-checker --namespace default --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete verifiers.config.ratify.deislabs.io/verifier-sbom --namespace default --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete verifiers.config.ratify.deislabs.io/verifier-schemavalidator --namespace default --ignore-not-found=true'
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
    run kubectl run schemavalidator --namespace default --image=registry:5000/schemavalidator:v0
    assert_success

    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_schemavalidator_bad.yaml
    assert_success
    # wait for the httpserver cache to be invalidated
    sleep 15
    run kubectl run schemavalidator2 --namespace default --image=registry:5000/schemavalidator:v0
    assert_failure
}

@test "vulnerabilityreport verifier test" {
    skip "TODO: migrate to v2 executor CRD"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete verifiers.config.ratify.deislabs.io/verifier-vulnerabilityreport --namespace default --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod vulnerabilityreport --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod vulnerabilityreport2 --namespace default --force --ignore-not-found=true'
    }

    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success
    sleep 5

    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_vulnerabilityreport2.yaml
    sleep 5
    run kubectl run vulnerabilityreport --namespace default --image=registry:5000/vulnerabilityreport:v0
    assert_success
    sleep 15
    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_vulnerabilityreport.yaml
    sleep 5
    run kubectl run vulnerabilityreport2 --namespace default --image=registry:5000/vulnerabilityreport:v0
    assert_failure
}

@test "sbom/notary/cosign/licensechecker/schemavalidator verifiers test" {
    skip "TODO: migrate to v2 executor CRD"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete verifiers.config.ratify.deislabs.io/verifier-license-checker --namespace default --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete verifiers.config.ratify.deislabs.io/verifier-sbom --namespace default --ignore-not-found=true'
        # Skipping test for now until expected usage/configuration of this plugin can be verified
        # wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete verifiers.config.ratify.deislabs.io/verifier-schemavalidator --namespace default --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod all-in-one --namespace default --force --ignore-not-found=true'
    }

    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success
    sleep 5

    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_cosign.yaml
    sleep 5
    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_sbom.yaml
    sleep 5
    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_complete_licensechecker.yaml
    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_schemavalidator.yaml
    sleep 5

    # wait for the httpserver cache to be invalidated
    sleep 15
    run kubectl run all-in-one --namespace default --image=registry:5000/all:v0
    assert_success
}

@test "namespaced sbom/notary/cosign/licensechecker/schemavalidator verifiers test" {
    skip "TODO: migrate to v2 executor CRD"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete namespacedverifiers.config.ratify.deislabs.io/verifier-license-checker --namespace default --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete namespacedverifiers.config.ratify.deislabs.io/verifier-sbom --namespace default --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete namespacedverifiers.config.ratify.deislabs.io/verifier-schemavalidator --namespace default --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete namespacedverifiers.config.ratify.deislabs.io/verifier-cosign --namespace default --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete namespacedverifiers.config.ratify.deislabs.io/verifier-notation --namespace default --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod all-in-one --namespace default --force --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_notation.yaml'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_cosign.yaml'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete namespacedkeymanagementproviders.config.ratify.deislabs.io/ratify-notation-inline-cert-0 -n default --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl apply -f clusternotationkmprovider.yaml'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete namespacedkeymanagementproviders.config.ratify.deislabs.io/ratify-cosign-inline-key-0 -n default --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl apply -f clustercosignkmprovider.yaml'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete namespacedpolicies.config.ratify.deislabs.io/ratify-policy --ignore-not-found=true'
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl apply -f clusterpolicy.yaml'
    }

    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    sleep 5
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success
    sleep 5

    run kubectl apply -f ./config/samples/namespaced/verifier/config_v1beta1_verifier_notation.yaml
    run kubectl delete verifiers.config.ratify.deislabs.io/verifier-notation --ignore-not-found=true
    run kubectl apply -f ./config/samples/namespaced/verifier/config_v1beta1_verifier_cosign.yaml
    run kubectl delete verifiers.config.ratify.deislabs.io/verifier-cosign --ignore-not-found=true
    run kubectl apply -f ./config/samples/namespaced/verifier/config_v1beta1_verifier_sbom.yaml
    run kubectl apply -f ./config/samples/namespaced/verifier/config_v1beta1_verifier_complete_licensechecker.yaml
    run kubectl apply -f ./config/samples/namespaced/verifier/config_v1beta1_verifier_schemavalidator.yaml

    # apply namespaced policy and delete clustered policy.
    run bash -c "kubectl get policies.config.ratify.deislabs.io/ratify-policy -o yaml > clusterpolicy.yaml"
    assert_success
    sed 's/kind: Policy/kind: NamespacedPolicy/;/^\s*resourceVersion:/d' clusterpolicy.yaml >namespacedpolicy.yaml
    run kubectl apply -f namespacedpolicy.yaml
    assert_success

    # apply namespaced kmp and delete clustered kmp.
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

    # wait for the httpserver cache to be invalidated
    sleep 15
    run kubectl run all-in-one --namespace default --image=registry:5000/all:v0
    assert_success
}

@test "validate crd add, replace and delete" {
    skip "TODO: migrate to v2 executor CRD"
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
    run kubectl run crdtest --namespace default --image=registry:5000/notation:signed
    assert_failure

    echo "Add notation verifier and validate deployment succeeds"
    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_notation.yaml
    assert_success

    # wait for the httpserver cache to be invalidated
    sleep 15
    run kubectl run crdtest --namespace default --image=registry:5000/notation:signed
    assert_success
}

@test "verifier crd status check" {
    skip "TODO: migrate to v2 executor CRD"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete verifiers.config.ratify.deislabs.io/verifier-license-checker'
    }

    # apply a valid verifier, validate status property shows success
    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_complete_licensechecker.yaml
    assert_success
    run bash -c "kubectl describe verifiers.config.ratify.deislabs.io/verifier-license-checker -n ${RATIFY_NAMESPACE} | grep 'Issuccess:  true'"
    assert_success

    # apply a invalid verifier CR, validate status with error
    sed 's/licensechecker/invalidlicensechecker/' ./config/samples/clustered/verifier/config_v1beta1_verifier_complete_licensechecker.yaml >invalidVerifier.yaml
    run kubectl apply -f invalidVerifier.yaml
    assert_success
    run bash -c "kubectl describe verifiers.config.ratify.deislabs.io/verifier-license-checker -n ${RATIFY_NAMESPACE} | grep 'Brieferror:  PLUGIN_NOT_FOUND:'"
    assert_success

    # apply a valid verifier, validate status property shows success
    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_complete_licensechecker.yaml
    assert_success
    run bash -c "kubectl describe verifiers.config.ratify.deislabs.io/verifier-license-checker -n ${RATIFY_NAMESPACE} | grep 'Issuccess:  true'"
    assert_success
    run bash -c "kubectl describe verifiers.config.ratify.deislabs.io/verifier-license-checker -n ${RATIFY_NAMESPACE} | grep 'Brieferror:  Original Error:'"
    assert_failure
}

@test "dynamic plugins disabled test" {
    skip "TODO: migrate to v2 executor CRD"
    teardown() {
        echo "cleaning up"
        wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete verifiers.config.ratify.deislabs.io/verifier-dynamic --namespace default --ignore-not-found=true'
    }

    start=$(date --iso-8601=seconds)
    latestpod=$(kubectl -n gatekeeper-system get pod -l=app.kubernetes.io/name=ratify --sort-by=.metadata.creationTimestamp -o=name | tail -n 1)

    run kubectl apply -f ./config/samples/clustered/verifier/config_v1beta1_verifier_dynamic.yaml
    sleep 5

    run bash -c "kubectl -n gatekeeper-system logs $latestpod --since-time=$start | grep 'dynamic plugins are currently disabled'"
    assert_success
}
