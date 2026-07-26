/*
Copyright The Ratify Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package podstatus contains helpers for the per-pod ExecutorPodStatus objects
// used to report per-replica Executor health without concurrent writers racing
// on a single shared status (the Gatekeeper *PodStatus pattern).
package podstatus

import (
	"encoding/base32"
	"fmt"
	"strings"
)

const (
	// LabelPodName is the label carrying the (sanitized) reporting pod name.
	LabelPodName = "internal.ratify.dev/pod-name"
	// LabelExecutorName is the label carrying the (sanitized) Executor name.
	LabelExecutorName = "internal.ratify.dev/executor-name"
)

// base32 without padding, lowercased, yields only [a-z2-7], which are all valid
// characters for a DNS-1123 subdomain (Kubernetes object name). Because the
// alphabet never contains '-', a single '-' is a safe, unambiguous separator
// between the two encoded segments.
var enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// PackName returns a deterministic, DNS-1123-compliant object name that embeds
// both the pod name and the executor name. Because the name is unique per
// (pod, executor) pair, no two pods ever target the same ExecutorPodStatus
// object, which eliminates write conflicts. The name is reversible via
// UnpackName so aggregation can recover the executor name even from a delete
// event (where only the object name is available).
func PackName(podName, executorName string) string {
	return encode(podName) + "-" + encode(executorName)
}

// UnpackName reverses PackName, returning the original pod and executor names.
func UnpackName(name string) (podName, executorName string, err error) {
	parts := strings.SplitN(name, "-", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid ExecutorPodStatus name %q: expected two dash-separated segments", name)
	}
	podName, err = decode(parts[0])
	if err != nil {
		return "", "", fmt.Errorf("invalid ExecutorPodStatus name %q: %w", name, err)
	}
	executorName, err = decode(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("invalid ExecutorPodStatus name %q: %w", name, err)
	}
	return podName, executorName, nil
}

func encode(s string) string {
	return strings.ToLower(enc.EncodeToString([]byte(s)))
}

func decode(s string) (string, error) {
	b, err := enc.DecodeString(strings.ToUpper(s))
	if err != nil {
		return "", err
	}
	return string(b), nil
}
