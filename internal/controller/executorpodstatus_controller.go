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
	"fmt"
	"sort"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	configv2alpha1 "github.com/notaryproject/ratify/v2/api/v2alpha1"
	"github.com/notaryproject/ratify/v2/internal/podstatus"
)

// ExecutorPodStatusReconciler watches all ExecutorPodStatus objects and folds
// the per-pod entries back into the owning Executor's status.byPod. This is the
// aggregation half of the Gatekeeper-style per-pod status pattern: individual
// pods only ever write their own ExecutorPodStatus object (no shared-status
// contention), and a single logical aggregation reconstructs the parent status.
//
// The aggregation is a full rebuild from the currently existing per-pod objects,
// so it is idempotent: a deleted pod's entry simply disappears from byPod on the
// next reconcile (its ExecutorPodStatus is garbage-collected via the pod owner
// reference, which fires a delete event that re-triggers aggregation).
type ExecutorPodStatusReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=config.ratify.sh,resources=executorpodstatuses,verbs=get;list;watch
// +kubebuilder:rbac:groups=config.ratify.sh,resources=executors,verbs=get;list;watch
// +kubebuilder:rbac:groups=config.ratify.sh,resources=executors/status,verbs=get;update;patch

// Reconcile aggregates all ExecutorPodStatus objects belonging to the same
// Executor as the reconciled object into Executor.status.byPod.
func (r *ExecutorPodStatusReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// The object may already be deleted; recover the executor name from the
	// (reversible) object name so aggregation still runs on delete events.
	_, executorName, err := podstatus.UnpackName(req.Name)
	if err != nil {
		log.Error(err, "Failed to decode ExecutorPodStatus name; skipping", "name", req.Name)
		return ctrl.Result{}, nil
	}

	var list configv2alpha1.ExecutorPodStatusList
	if err := r.List(ctx, &list); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list ExecutorPodStatus objects: %w", err)
	}

	byPod := make([]configv2alpha1.PodStatusEntry, 0, len(list.Items))
	for i := range list.Items {
		_, itemExecutor, decErr := podstatus.UnpackName(list.Items[i].Name)
		if decErr != nil {
			continue
		}
		if itemExecutor == executorName {
			byPod = append(byPod, list.Items[i].Status)
		}
	}
	sort.Slice(byPod, func(i, j int) bool { return byPod[i].ID < byPod[j].ID })

	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var executor configv2alpha1.Executor
		if getErr := r.Get(ctx, types.NamespacedName{Name: executorName}, &executor); getErr != nil {
			return getErr
		}
		applyAggregatedStatus(&executor, byPod)
		return r.Status().Update(ctx, &executor)
	})
	if apierrors.IsNotFound(retryErr) {
		// The Executor is gone; nothing to aggregate.
		return ctrl.Result{}, nil
	}
	if retryErr != nil {
		return ctrl.Result{}, fmt.Errorf("failed to aggregate status for Executor %q: %w", executorName, retryErr)
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager. Note: no
// GenerationChangedPredicate here — per-pod status writes do not bump
// generation, yet they are exactly the events aggregation must react to.
// This watch does not create a feedback loop because it only writes the
// Executor status (never ExecutorPodStatus), and the Executor watch is itself
// filtered by generation.
func (r *ExecutorPodStatusReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&configv2alpha1.ExecutorPodStatus{}).
		Complete(r)
}

// applyAggregatedStatus recomputes the Executor's aggregate status from the
// per-pod entries. The top-level Succeeded is true only when at least one pod
// reported and every reporting pod succeeded; otherwise Error summarizes how
// many replicas are unhealthy.
func applyAggregatedStatus(executor *configv2alpha1.Executor, byPod []configv2alpha1.PodStatusEntry) {
	executor.Status.ByPod = byPod

	total := len(byPod)
	failing := 0
	firstErr := ""
	for _, entry := range byPod {
		if !entry.Succeeded {
			failing++
			if firstErr == "" {
				firstErr = entry.Error
			}
		}
	}

	if total > 0 && failing == 0 {
		executor.Status.Succeeded = true
		executor.Status.Error = ""
		executor.Status.BriefError = ""
		return
	}

	executor.Status.Succeeded = false
	if total == 0 {
		executor.Status.Error = ""
		executor.Status.BriefError = ""
		return
	}
	msg := fmt.Sprintf("%d/%d replicas unhealthy: %s", failing, total, firstErr)
	executor.Status.Error = msg
	executor.Status.BriefError = briefError(msg)
}
