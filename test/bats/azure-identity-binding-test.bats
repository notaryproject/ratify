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

# AKS identity binding end-to-end test for the ratify v2 gatekeeper provider.
# See scripts/azure-ci-test-identity-binding.sh for the deployment.
#
# ratify is deployed with the ACR "azure" credential provider in identity
# binding mode. Because the test ACR requires authentication, ratify can only
# fetch the image manifest and notation signature after successfully exchanging
# the projected service account token (audience api://AKSIdentityBinding) for an
# AAD token and then an ACR refresh token. Admission of the signed image
# therefore proves the identity binding based registry authentication worked
# end-to-end; the unsigned image confirms verification is actually enforced.

load helpers

BATS_TESTS_DIR=${BATS_TESTS_DIR:-test/bats/tests}
WAIT_TIME=60
SLEEP_TIME=1
RATIFY_NAMESPACE=gatekeeper-system

@test "notation identity binding test" {
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

    # Signed image: ratify authenticates to ACR via identity binding, pulls the
    # manifest and notation signature, and verifies against the inline trust
    # store. Admission must succeed.
    run wait_for_process 20 10 'kubectl run demo --namespace default --image=${TEST_REGISTRY}/notation:signed'
    assert_success

    # Unsigned image must be rejected, confirming verification is enforced.
    run kubectl run demo1 --namespace default --image=${TEST_REGISTRY}/notation:unsigned
    assert_failure
}
