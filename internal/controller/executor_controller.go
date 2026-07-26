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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	configv2alpha1 "github.com/notaryproject/ratify/v2/api/v2alpha1"
)

// ExecutorReconciler reconciles a Executor object
type ExecutorReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=config.ratify.dev,resources=executors,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=config.ratify.dev,resources=executors/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=config.ratify.dev,resources=executors/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Executor object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
func (r *ExecutorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var executor configv2alpha1.Executor
	log.Info("Reconciling Executor", "executor", req.Name)

	if err := r.Get(ctx, req.NamespacedName, &executor); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("Executor resource not found, ignoring since object must be deleted")
			if err := GlobalExecutorManager.deleteExecutor(req.Namespace, req.Name); err != nil {
				log.Error(err, "Failed to delete Executor from GlobalExecutorManager", "executor", req.Name)
			}
		} else {
			log.Error(err, "Failed to get Executor", "executor", req.Name)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	err := GlobalExecutorManager.upsertExecutor(req.Namespace, req.Name, &executor)
	if err != nil {
		log.Error(err, "Failed to upsert Executor", "executor", req.Name)
	}

	r.updateStatus(ctx, &executor, err)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
//
// The watch is filtered with GenerationChangedPredicate so that status-only
// updates (which do not bump metadata.generation) do not re-trigger Reconcile.
// Without this predicate every status write produced by updateStatus would
// itself be an update event that re-enqueues the object, creating a feedback
// loop that repeatedly rebuilds the in-memory executor (and hammers external
// providers such as Azure Key Vault). The loop is amplified once the
// deployment is scaled to multiple replicas.
func (r *ExecutorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&configv2alpha1.Executor{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

// updateStatus records the outcome of the reconcile on the Executor's status
// subresource.
//
// The write is wrapped in retry.RetryOnConflict so that concurrent writers
// (e.g. multiple replicas, or an informer resync racing a spec change) do not
// silently drop the update on an HTTP 409. On conflict the object is re-fetched
// to obtain the latest resourceVersion before the status is re-applied.
func (r *ExecutorReconciler) updateStatus(ctx context.Context, executor *configv2alpha1.Executor, upsertErr error) {
	log := logf.FromContext(ctx)
	key := types.NamespacedName{Namespace: executor.Namespace, Name: executor.Name}

	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var latest configv2alpha1.Executor
		if getErr := r.Get(ctx, key, &latest); getErr != nil {
			return getErr
		}
		if upsertErr != nil {
			latest.Status.Succeeded = false
			latest.Status.Error = upsertErr.Error()
		} else {
			latest.Status.Succeeded = true
			latest.Status.Error = ""
		}
		return r.Status().Update(ctx, &latest)
	})
	if retryErr != nil {
		log.Error(retryErr, "Failed to update Executor status", "executor", executor.Name)
	}
}
