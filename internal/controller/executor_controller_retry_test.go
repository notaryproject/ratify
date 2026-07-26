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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	configv2alpha1 "github.com/notaryproject/ratify/v2/api/v2alpha1"
)

func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := configv2alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}
	return scheme
}

// TestUpdateStatusRetriesOnConflict verifies that updateStatus does not silently
// drop the status write when the first Status().Update returns an HTTP 409
// conflict, but instead re-fetches and retries until it succeeds.
func TestUpdateStatusRetriesOnConflict(t *testing.T) {
	scheme := newTestScheme(t)
	executor := &configv2alpha1.Executor{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
	}

	var updateAttempts int
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(executor).
		WithStatusSubresource(executor).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, cl client.Client, _ string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
				updateAttempts++
				if updateAttempts == 1 {
					// Simulate another writer winning the optimistic-concurrency
					// race on the first attempt.
					return apierrors.NewConflict(
						schema.GroupResource{Group: "config.ratify.sh", Resource: "executors"},
						obj.GetName(),
						errors.New("the object has been modified"),
					)
				}
				return cl.Status().Update(ctx, obj, opts...)
			},
		}).
		Build()

	r := &ExecutorReconciler{Client: c, Scheme: scheme}
	r.updateStatus(context.Background(), executor, nil)

	if updateAttempts < 2 {
		t.Fatalf("expected updateStatus to retry after a conflict, got %d attempt(s)", updateAttempts)
	}

	var got configv2alpha1.Executor
	if err := c.Get(context.Background(), types.NamespacedName{Name: "test", Namespace: "default"}, &got); err != nil {
		t.Fatalf("failed to get executor: %v", err)
	}
	if !got.Status.Succeeded {
		t.Errorf("expected Status.Succeeded to be true after retry, got false")
	}
	if got.Status.Error != "" {
		t.Errorf("expected empty Status.Error, got %q", got.Status.Error)
	}
}

// TestUpdateStatusRecordsError verifies that a non-nil upsert error is persisted
// to the Executor status.
func TestUpdateStatusRecordsError(t *testing.T) {
	scheme := newTestScheme(t)
	executor := &configv2alpha1.Executor{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(executor).
		WithStatusSubresource(executor).
		Build()

	r := &ExecutorReconciler{Client: c, Scheme: scheme}
	r.updateStatus(context.Background(), executor, errors.New("boom"))

	var got configv2alpha1.Executor
	if err := c.Get(context.Background(), types.NamespacedName{Name: "test", Namespace: "default"}, &got); err != nil {
		t.Fatalf("failed to get executor: %v", err)
	}
	if got.Status.Succeeded {
		t.Errorf("expected Status.Succeeded to be false")
	}
	if got.Status.Error != "boom" {
		t.Errorf("expected Status.Error to be %q, got %q", "boom", got.Status.Error)
	}
}
