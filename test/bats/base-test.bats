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

WAIT_TIME=60
SLEEP_TIME=1
RATIFY_NAMESPACE=gatekeeper-system
EXECUTOR_NAME=ratify-ratify-gatekeeper-provider-executor-1

setup() {
    run kubectl apply -f ./library/multi-tenancy-validation/template.yaml
    assert_success
    run kubectl apply -f ./library/multi-tenancy-validation/samples/constraint.yaml
    assert_success
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o jsonpath='{.status.succeeded}' | grep true"
}

teardown() {
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo-signed --namespace default --force --ignore-not-found=true'
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo-unsigned --namespace default --force --ignore-not-found=true'
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} 'kubectl delete pod demo-out-of-scope --namespace default --force --ignore-not-found=true'
    kubectl patch executors.config.ratify.dev/${EXECUTOR_NAME} --type=json -p='[{"op":"replace","path":"/spec/scopes","value":["registry:5000"]}]' >/dev/null 2>&1 || true
    wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o jsonpath='{.status.succeeded}' | grep true"
}

@test "executor admits signed notation image" {
    run kubectl run demo-signed --namespace default --image=registry:5000/notation:signed
    assert_success
}

@test "executor rejects unsigned image" {
    run kubectl run demo-unsigned --namespace default --image=registry:5000/notation:unsigned
    assert_failure
}

@test "executor reports succeeded status" {
    run kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o jsonpath='{.status.succeeded}'
    assert_success
    [ "$output" = "true" ]
}

@test "executor scope updates take effect" {
    run kubectl patch executors.config.ratify.dev/${EXECUTOR_NAME} --type=json -p='[{"op":"replace","path":"/spec/scopes","value":["registry:5000/notation"]}]'
    assert_success

    sleep 10

    run kubectl get executors.config.ratify.dev/${EXECUTOR_NAME} -o jsonpath='{.status.succeeded}'
    assert_success
    [ "$output" = "true" ]

    run kubectl run demo-signed --namespace default --image=registry:5000/notation:signed
    assert_success

    # Image outside the narrowed scope should be rejected by gatekeeper (no executor covers it)
    run kubectl run demo-out-of-scope --namespace default --image=registry:5000/all:v0
    assert_failure
}
