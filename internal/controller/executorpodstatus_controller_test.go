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

package controller

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv2alpha1 "github.com/notaryproject/ratify/v2/api/v2alpha1"
	"github.com/notaryproject/ratify/v2/internal/podstatus"
)

func typesName(name string) types.NamespacedName {
	return types.NamespacedName{Name: name}
}

func reconcileRequest(name string) reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{Name: name}}
}

func newPodStatusScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add clientgo scheme: %v", err)
	}
	if err := configv2alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add ratify scheme: %v", err)
	}
	return scheme
}

// TestUpsertPodStatusWritesPerPodObject verifies that when the pod identity is
// known, the reconciler writes a dedicated ExecutorPodStatus object (named for
// the pod+executor) instead of touching Executor.status directly.
func TestUpsertPodStatusWritesPerPodObject(t *testing.T) {
	scheme := newPodStatusScheme(t)
	executor := &configv2alpha1.Executor{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Generation: 3},
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "ratify-0", Namespace: "ratify-system", UID: "uid-123"}}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(executor, pod).
		WithStatusSubresource(&configv2alpha1.Executor{}, &configv2alpha1.ExecutorPodStatus{}).
		Build()

	r := &ExecutorReconciler{Client: c, Scheme: scheme, PodName: "ratify-0", PodNamespace: "ratify-system"}
	r.updateStatus(context.Background(), executor, nil)

	name := podstatus.PackName("ratify-0", "default")
	var ps configv2alpha1.ExecutorPodStatus
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "ratify-system", Name: name}, &ps); err != nil {
		t.Fatalf("expected ExecutorPodStatus %q to exist: %v", name, err)
	}
	if !ps.Status.Succeeded {
		t.Errorf("expected per-pod status Succeeded=true")
	}
	if ps.Status.ID != "ratify-0" {
		t.Errorf("expected status.id=ratify-0, got %q", ps.Status.ID)
	}
	if ps.Status.ObservedGeneration != 3 {
		t.Errorf("expected observedGeneration=3, got %d", ps.Status.ObservedGeneration)
	}
	// Owner reference to the pod enables garbage collection.
	if len(ps.OwnerReferences) != 1 || ps.OwnerReferences[0].Name != "ratify-0" {
		t.Errorf("expected owner reference to pod ratify-0, got %+v", ps.OwnerReferences)
	}
	// Executor.status must NOT have been written directly by the pod.
	var gotExec configv2alpha1.Executor
	if err := c.Get(context.Background(), typesName("default"), &gotExec); err != nil {
		t.Fatalf("get executor: %v", err)
	}
	if gotExec.Status.Succeeded {
		t.Errorf("expected Executor.status.succeeded to be untouched (false) by per-pod path")
	}
}

func TestUpsertPodStatusRecordsError(t *testing.T) {
	scheme := newPodStatusScheme(t)
	executor := &configv2alpha1.Executor{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(executor).
		WithStatusSubresource(&configv2alpha1.Executor{}, &configv2alpha1.ExecutorPodStatus{}).
		Build()

	r := &ExecutorReconciler{Client: c, Scheme: scheme, PodName: "ratify-1", PodNamespace: "ratify-system"}
	r.updateStatus(context.Background(), executor, errors.New("akv unreachable"))

	var ps configv2alpha1.ExecutorPodStatus
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "ratify-system", Name: podstatus.PackName("ratify-1", "default")}, &ps); err != nil {
		t.Fatalf("get pod status: %v", err)
	}
	if ps.Status.Succeeded {
		t.Errorf("expected Succeeded=false")
	}
	if ps.Status.Error != "akv unreachable" {
		t.Errorf("expected error recorded, got %q", ps.Status.Error)
	}
}

// TestApplyAggregatedStatus checks the pure aggregation logic.
func TestApplyAggregatedStatus(t *testing.T) {
	t.Run("all healthy", func(t *testing.T) {
		var e configv2alpha1.Executor
		applyAggregatedStatus(&e, []configv2alpha1.PodStatusEntry{
			{ID: "a", Succeeded: true},
			{ID: "b", Succeeded: true},
		})
		if !e.Status.Succeeded || e.Status.Error != "" || len(e.Status.ByPod) != 2 {
			t.Errorf("unexpected status: %+v", e.Status)
		}
	})
	t.Run("some unhealthy", func(t *testing.T) {
		var e configv2alpha1.Executor
		applyAggregatedStatus(&e, []configv2alpha1.PodStatusEntry{
			{ID: "a", Succeeded: true},
			{ID: "b", Succeeded: false, Error: "boom"},
		})
		if e.Status.Succeeded {
			t.Errorf("expected Succeeded=false")
		}
		if e.Status.Error == "" {
			t.Errorf("expected aggregated error message")
		}
	})
	t.Run("no pods", func(t *testing.T) {
		var e configv2alpha1.Executor
		applyAggregatedStatus(&e, nil)
		if e.Status.Succeeded {
			t.Errorf("expected Succeeded=false when no pods reported")
		}
	})
}

// TestAggregatorReconcile verifies the aggregation reconciler folds per-pod
// objects into Executor.status.byPod.
func TestAggregatorReconcile(t *testing.T) {
	scheme := newPodStatusScheme(t)
	executor := &configv2alpha1.Executor{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	ps1 := &configv2alpha1.ExecutorPodStatus{
		ObjectMeta: metav1.ObjectMeta{Name: podstatus.PackName("pod-1", "default"), Namespace: "ratify-system"},
		Status:     configv2alpha1.PodStatusEntry{ID: "pod-1", Succeeded: true},
	}
	ps2 := &configv2alpha1.ExecutorPodStatus{
		ObjectMeta: metav1.ObjectMeta{Name: podstatus.PackName("pod-2", "default"), Namespace: "ratify-system"},
		Status:     configv2alpha1.PodStatusEntry{ID: "pod-2", Succeeded: false, Error: "akv"},
	}
	// A pod status belonging to a different executor must be ignored.
	psOther := &configv2alpha1.ExecutorPodStatus{
		ObjectMeta: metav1.ObjectMeta{Name: podstatus.PackName("pod-1", "other"), Namespace: "ratify-system"},
		Status:     configv2alpha1.PodStatusEntry{ID: "pod-1", Succeeded: true},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(executor, ps1, ps2, psOther).
		WithStatusSubresource(&configv2alpha1.Executor{}, &configv2alpha1.ExecutorPodStatus{}).
		Build()

	r := &ExecutorPodStatusReconciler{Client: c, Scheme: scheme}
	if _, err := r.Reconcile(context.Background(), reconcileRequest(ps1.Name)); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var got configv2alpha1.Executor
	if err := c.Get(context.Background(), typesName("default"), &got); err != nil {
		t.Fatalf("get executor: %v", err)
	}
	if len(got.Status.ByPod) != 2 {
		t.Fatalf("expected 2 byPod entries, got %d: %+v", len(got.Status.ByPod), got.Status.ByPod)
	}
	if got.Status.Succeeded {
		t.Errorf("expected aggregate Succeeded=false because pod-2 failed")
	}
}
