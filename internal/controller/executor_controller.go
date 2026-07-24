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
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	configv2alpha1 "github.com/notaryproject/ratify/v2/api/v2alpha1"
)

// statusSyncInterval is how often a non-leader replica requeues an Executor
// whose status has not yet been written. Because the reconciler runs on every
// replica (see SetupWithManager) it may reconcile existing Executors before any
// replica has acquired leadership; requeuing ensures the elected leader
// eventually writes status for objects that predate leadership.
const statusSyncInterval = 30 * time.Second

// ExecutorReconciler reconciles a Executor object
type ExecutorReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// Elected is closed once this replica has been elected leader, or
	// immediately when leader election is disabled. The reconciler runs on
	// every replica so each replica keeps its in-memory executor up to date,
	// but only the leader writes Executor status to avoid redundant writes from
	// every replica. A nil channel is treated as elected.
	Elected <-chan struct{}
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

	// All replicas update their in-memory executor above, but only the leader
	// writes status to avoid redundant writes from every replica.
	if r.isLeader() {
		r.updateStatus(ctx, &executor, err)
		return ctrl.Result{}, nil
	}

	// This replica is not (yet) the leader and therefore does not write status.
	// The controller runs on every replica and may reconcile existing Executors
	// before any replica has acquired leadership. Requeue until the status
	// reflects the current result so the elected leader eventually writes it;
	// non-leaders stop requeuing once the leader has updated the status.
	if !statusUpToDate(&executor, err) {
		return ctrl.Result{RequeueAfter: statusSyncInterval}, nil
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ExecutorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Run the reconciler on every replica (not only the leader) so each replica
	// maintains its own in-memory executor. Leadership is only used to decide
	// which replica writes Executor status (see Reconcile and isLeader).
	needLeaderElection := false
	return ctrl.NewControllerManagedBy(mgr).
		For(&configv2alpha1.Executor{}).
		WithOptions(controller.Options{NeedLeaderElection: &needLeaderElection}).
		Complete(r)
}

// isLeader reports whether this replica is the elected leader and therefore
// responsible for writing Executor status. A nil Elected channel (for example
// in tests or when leader election is disabled) is treated as elected.
func (r *ExecutorReconciler) isLeader() bool {
	if r.Elected == nil {
		return true
	}
	select {
	case <-r.Elected:
		return true
	default:
		return false
	}
}

// statusUpToDate reports whether the Executor's persisted status already
// reflects the result of the latest reconcile, so a non-leader replica can stop
// requeuing once the leader has written status.
func statusUpToDate(executor *configv2alpha1.Executor, err error) bool {
	if err != nil {
		return !executor.Status.Succeeded && executor.Status.Error == err.Error()
	}
	return executor.Status.Succeeded && executor.Status.Error == ""
}

func (r *ExecutorReconciler) updateStatus(ctx context.Context, executor *configv2alpha1.Executor, err error) {
	if err != nil {
		executor.Status.Succeeded = false
		executor.Status.Error = err.Error()
	} else {
		executor.Status.Succeeded = true
		executor.Status.Error = ""
	}
	if statusErr := r.Status().Update(ctx, executor); statusErr != nil {
		log := logf.FromContext(ctx)
		log.Error(statusErr, "Failed to update Executor status", "executor", executor.Name)
	}
}
