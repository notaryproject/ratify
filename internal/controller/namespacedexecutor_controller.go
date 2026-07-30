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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	configv2alpha1 "github.com/notaryproject/ratify/v2/api/v2alpha1"
)

// NamespacedExecutorReconciler reconciles a NamespacedExecutor object. Each
// NamespacedExecutor contributes to the executor bucket of its own namespace,
// enabling per-namespace (multi-tenant) validation configuration.
type NamespacedExecutorReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=config.ratify.sh,resources=namespacedexecutors,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=config.ratify.sh,resources=namespacedexecutors/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=config.ratify.sh,resources=namespacedexecutors/finalizers,verbs=update

// Reconcile keeps the executor for the resource's namespace in sync with the
// desired state described by the NamespacedExecutor object.
func (r *NamespacedExecutorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var executor configv2alpha1.NamespacedExecutor
	log.Info("Reconciling NamespacedExecutor", "namespace", req.Namespace, "executor", req.Name)

	if err := r.Get(ctx, req.NamespacedName, &executor); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("NamespacedExecutor resource not found, ignoring since object must be deleted")
			if err := GlobalExecutorManager.deleteExecutor(req.Namespace, req.Name); err != nil {
				log.Error(err, "Failed to delete NamespacedExecutor from GlobalExecutorManager", "namespace", req.Namespace, "executor", req.Name)
			}
		} else {
			log.Error(err, "Failed to get NamespacedExecutor", "namespace", req.Namespace, "executor", req.Name)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	err := GlobalExecutorManager.upsertExecutor(req.Namespace, req.Name, &executor.Spec)
	if err != nil {
		log.Error(err, "Failed to upsert NamespacedExecutor", "namespace", req.Namespace, "executor", req.Name)
	}

	r.updateStatus(ctx, &executor, err)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NamespacedExecutorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&configv2alpha1.NamespacedExecutor{}).
		Complete(r)
}

func (r *NamespacedExecutorReconciler) updateStatus(ctx context.Context, executor *configv2alpha1.NamespacedExecutor, err error) {
	if err != nil {
		executor.Status.Succeeded = false
		executor.Status.Error = err.Error()
	} else {
		executor.Status.Succeeded = true
		executor.Status.Error = ""
	}
	if statusErr := r.Status().Update(ctx, executor); statusErr != nil {
		log := logf.FromContext(ctx)
		log.Error(statusErr, "Failed to update NamespacedExecutor status", "namespace", executor.Namespace, "executor", executor.Name)
	}
}
