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
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	configv2alpha1 "github.com/notaryproject/ratify/v2/api/v2alpha1"
	"github.com/notaryproject/ratify/v2/internal/podstatus"
)

// TestDeletePodStatus verifies the per-pod status object is removed for the
// reporting pod, that deleting a missing object is a no-op, and that the delete
// is skipped entirely when the pod identity is unknown.
func TestDeletePodStatus(t *testing.T) {
	scheme := newPodStatusScheme(t)
	name := podstatus.PackName("ratify-9", "default")
	ps := &configv2alpha1.ExecutorPodStatus{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ratify-system"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ps).Build()

	r := &ExecutorReconciler{Client: c, Scheme: scheme, PodName: "ratify-9", PodNamespace: "ratify-system"}
	if err := r.deletePodStatus(context.Background(), "default"); err != nil {
		t.Fatalf("deletePodStatus: %v", err)
	}
	var got configv2alpha1.ExecutorPodStatus
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "ratify-system", Name: name}, &got); err == nil {
		t.Errorf("expected ExecutorPodStatus %q to be deleted", name)
	}

	// Deleting again (object already gone) must not error.
	if err := r.deletePodStatus(context.Background(), "default"); err != nil {
		t.Errorf("expected delete of missing object to be a no-op, got %v", err)
	}

	// When the pod identity is unknown, the delete is skipped without error.
	rNoPod := &ExecutorReconciler{Client: c, Scheme: scheme}
	if err := rNoPod.deletePodStatus(context.Background(), "default"); err != nil {
		t.Errorf("expected no-op when PodName is empty, got %v", err)
	}
}

// TestBriefError checks that short messages pass through unchanged and long ones
// are truncated to maxBriefErrorLength characters plus an ellipsis.
func TestBriefError(t *testing.T) {
	if got := briefError("short"); got != "short" {
		t.Errorf("expected short message unchanged, got %q", got)
	}
	long := strings.Repeat("x", maxBriefErrorLength+50)
	got := briefError(long)
	if len(got) != maxBriefErrorLength+len("...") || !strings.HasSuffix(got, "...") {
		t.Errorf("expected truncation to %d chars + ellipsis, got len=%d", maxBriefErrorLength, len(got))
	}
}

// TestSanitizeLabelValue exercises the character-replacement, end-trimming,
// empty-fallback, and length-capping branches.
func TestSanitizeLabelValue(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"already valid", "ratify-0", "ratify-0"},
		{"invalid chars replaced", "a/b:c", "a-b-c"},
		{"non-alnum ends trimmed", "-.abc._", "abc"},
		{"all invalid falls back", "///", unknownLabelValue},
		{"empty falls back", "", unknownLabelValue},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeLabelValue(tc.in); got != tc.want {
				t.Errorf("sanitizeLabelValue(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	// Values longer than 63 characters are capped to the label-length limit.
	if got := sanitizeLabelValue(strings.Repeat("a", 100)); len(got) > 63 {
		t.Errorf("expected sanitized value <=63 chars, got %d", len(got))
	}
}

// TestUpsertPodStatusRetriesOnConflict verifies the per-pod status write
// re-fetches and retries when the first status update loses the
// optimistic-concurrency race, rather than dropping the update.
func TestUpsertPodStatusRetriesOnConflict(t *testing.T) {
	scheme := newPodStatusScheme(t)
	executor := &configv2alpha1.Executor{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "ratify-2", Namespace: "ratify-system", UID: "uid-2"}}

	var attempts int
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(executor, pod).
		WithStatusSubresource(&configv2alpha1.Executor{}, &configv2alpha1.ExecutorPodStatus{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, cl client.Client, _ string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
				if _, ok := obj.(*configv2alpha1.ExecutorPodStatus); ok {
					attempts++
					if attempts == 1 {
						return apierrors.NewConflict(
							schema.GroupResource{Group: "config.ratify.sh", Resource: "executorpodstatuses"},
							obj.GetName(),
							errors.New("the object has been modified"),
						)
					}
				}
				return cl.Status().Update(ctx, obj, opts...)
			},
		}).
		Build()

	r := &ExecutorReconciler{Client: c, Scheme: scheme, PodName: "ratify-2", PodNamespace: "ratify-system"}
	r.updateStatus(context.Background(), executor, nil)

	if attempts < 2 {
		t.Fatalf("expected the status write to retry after a conflict, got %d attempt(s)", attempts)
	}
	var ps configv2alpha1.ExecutorPodStatus
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "ratify-system", Name: podstatus.PackName("ratify-2", "default")}, &ps); err != nil {
		t.Fatalf("get pod status: %v", err)
	}
	if !ps.Status.Succeeded {
		t.Errorf("expected per-pod Succeeded=true after the retry")
	}
}

// TestAggregatorReconcileUndecodableName verifies that a request whose name is
// not a valid packed ExecutorPodStatus name is skipped without error.
func TestAggregatorReconcileUndecodableName(t *testing.T) {
	scheme := newPodStatusScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	r := &ExecutorPodStatusReconciler{Client: c, Scheme: scheme}
	// A name without the dash separator cannot be unpacked.
	if _, err := r.Reconcile(context.Background(), reconcileRequest("nodashsegment")); err != nil {
		t.Errorf("expected undecodable name to be skipped without error, got %v", err)
	}
}

// TestAggregatorReconcileExecutorGone verifies aggregation is a no-op when the
// owning Executor no longer exists.
func TestAggregatorReconcileExecutorGone(t *testing.T) {
	scheme := newPodStatusScheme(t)
	ps := &configv2alpha1.ExecutorPodStatus{
		ObjectMeta: metav1.ObjectMeta{Name: podstatus.PackName("pod-1", "gone"), Namespace: "ratify-system"},
		Status:     configv2alpha1.PodStatusEntry{ID: "pod-1", Succeeded: true},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ps).
		WithStatusSubresource(&configv2alpha1.Executor{}, &configv2alpha1.ExecutorPodStatus{}).
		Build()

	r := &ExecutorPodStatusReconciler{Client: c, Scheme: scheme}
	if _, err := r.Reconcile(context.Background(), reconcileRequest(ps.Name)); err != nil {
		t.Errorf("expected no error when the Executor is gone, got %v", err)
	}
}

// TestUpsertPodStatusCreateError verifies that a failure to create the per-pod
// object is handled gracefully (logged, no status object left behind).
func TestUpsertPodStatusCreateError(t *testing.T) {
	scheme := newPodStatusScheme(t)
	executor := &configv2alpha1.Executor{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(executor).
		WithStatusSubresource(&configv2alpha1.Executor{}, &configv2alpha1.ExecutorPodStatus{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.CreateOption) error {
				return errors.New("create rejected")
			},
		}).
		Build()

	r := &ExecutorReconciler{Client: c, Scheme: scheme, PodName: "ratify-3", PodNamespace: "ratify-system"}
	r.updateStatus(context.Background(), executor, nil)

	var ps configv2alpha1.ExecutorPodStatus
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "ratify-system", Name: podstatus.PackName("ratify-3", "default")}, &ps); err == nil {
		t.Errorf("expected no ExecutorPodStatus to exist when create fails")
	}
}

// TestUpdateExecutorStatusDirectlyGetError verifies the single-writer fallback
// tolerates a failed re-fetch without panicking.
func TestUpdateExecutorStatusDirectlyGetError(t *testing.T) {
	scheme := newTestScheme(t)
	executor := &configv2alpha1.Executor{ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"}}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(executor).
		WithStatusSubresource(executor).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return errors.New("get failed")
			},
		}).
		Build()

	// PodName empty -> the direct write path is used; its Get fails.
	r := &ExecutorReconciler{Client: c, Scheme: scheme}
	r.updateStatus(context.Background(), executor, nil)
}

// TestAggregatorReconcileListError verifies the aggregator surfaces a failure to
// list ExecutorPodStatus objects as a reconcile error (so it is retried).
func TestAggregatorReconcileListError(t *testing.T) {
	scheme := newPodStatusScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
				return errors.New("list failed")
			},
		}).
		Build()

	r := &ExecutorPodStatusReconciler{Client: c, Scheme: scheme}
	if _, err := r.Reconcile(context.Background(), reconcileRequest(podstatus.PackName("pod-1", "default"))); err == nil {
		t.Errorf("expected an error when listing ExecutorPodStatus fails")
	}
}
