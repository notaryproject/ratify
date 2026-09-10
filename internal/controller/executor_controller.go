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

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	configv2alpha1 "github.com/notaryproject/ratify/v2/api/v2alpha1"
	"github.com/notaryproject/ratify/v2/internal/podstatus"
)

// maxBriefErrorLength is the maximum length of the BriefError field. Longer
// error messages are truncated to keep the status compact.
const maxBriefErrorLength = 120

// executorRetryInterval is how long to wait before re-driving an Executor whose
// build failed. The Executor watch is filtered by GenerationChangedPredicate,
// so a periodic requeue is what lets a transient build failure (for example a
// dependent Secret/cert or Key Vault that is not ready yet at startup) recover
// without waiting for a spec change.
const executorRetryInterval = 15 * time.Second

// unknownLabelValue is the placeholder label value used when a pod/executor name
// sanitizes to the empty string.
const unknownLabelValue = "unknown"

// ExecutorReconciler reconciles a Executor object.
//
// Every Ratify replica runs its own ExecutorReconciler: each pod builds its own
// in-memory executor (the data plane serves verification requests from it) and
// reports its own health into a dedicated per-pod ExecutorPodStatus object.
// Because each pod writes a distinct object (the name embeds the pod identity),
// there is no shared-status write contention between replicas.
type ExecutorReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// PodName and PodNamespace identify the pod this reconciler runs in. They
	// are used to name and own the per-pod ExecutorPodStatus object. When
	// PodName is empty (e.g. running outside a cluster), status reporting falls
	// back to writing the Executor status directly.
	PodName      string
	PodNamespace string
}

// +kubebuilder:rbac:groups=config.ratify.sh,resources=executors,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=config.ratify.sh,resources=executors/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=config.ratify.sh,resources=executors/finalizers,verbs=update
// +kubebuilder:rbac:groups=config.ratify.sh,resources=executorpodstatuses,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=config.ratify.sh,resources=executorpodstatuses/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
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
			// The Executor is gone; remove this pod's per-pod status object so
			// it does not linger (its owner reference is the pod, not the
			// Executor, so it is not garbage-collected on Executor deletion).
			if delErr := r.deletePodStatus(ctx, req.Name); delErr != nil {
				log.Error(delErr, "Failed to delete ExecutorPodStatus", "executor", req.Name)
			}
		} else {
			log.Error(err, "Failed to get Executor", "executor", req.Name)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	err := GlobalExecutorManager.upsertExecutor(req.Namespace, req.Name, &executor.Spec)
	if err != nil {
		log.Error(err, "Failed to upsert Executor", "executor", req.Name)
	}

	r.updateStatus(ctx, &executor, err)

	// Requeue after a failed build so a transient startup error (for example a
	// dependent Secret, certificate, or Key Vault that is not ready yet)
	// recovers on its own: the Executor watch is filtered by generation, so
	// nothing else would re-drive this reconcile until the spec changes. The
	// error is deliberately not returned (it is already recorded in status) to
	// avoid inflating reconcile-error metrics.
	result := ctrl.Result{}
	if err != nil {
		result.RequeueAfter = executorRetryInterval
	}
	return result, nil
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

// updateStatus records the outcome of the reconcile for this pod.
//
// When the pod identity is known, the outcome is written to a dedicated per-pod
// ExecutorPodStatus object (owned by the pod for automatic garbage collection),
// which a separate aggregation controller folds into Executor.status.byPod.
// This avoids all replicas writing the same Executor.status concurrently. When
// the pod identity is unknown, it falls back to writing the Executor status
// directly (single-writer, e.g. out-of-cluster usage).
func (r *ExecutorReconciler) updateStatus(ctx context.Context, executor *configv2alpha1.Executor, upsertErr error) {
	if r.PodName == "" {
		r.updateExecutorStatusDirectly(ctx, executor, upsertErr)
		return
	}
	r.upsertPodStatus(ctx, executor, upsertErr)
}

// upsertPodStatus creates or updates this pod's ExecutorPodStatus object.
func (r *ExecutorReconciler) upsertPodStatus(ctx context.Context, executor *configv2alpha1.Executor, upsertErr error) {
	log := logf.FromContext(ctx)
	name := podstatus.PackName(r.PodName, executor.Name)

	ps := &configv2alpha1.ExecutorPodStatus{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: r.PodNamespace},
	}

	// Ensure the object exists with the correct labels and owner reference.
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, ps, func() error {
		if ps.Labels == nil {
			ps.Labels = map[string]string{}
		}
		ps.Labels[podstatus.LabelPodName] = sanitizeLabelValue(r.PodName)
		ps.Labels[podstatus.LabelExecutorName] = sanitizeLabelValue(executor.Name)
		r.setPodOwnerReference(ctx, ps)
		return nil
	}); err != nil {
		log.Error(err, "Failed to upsert ExecutorPodStatus object", "executorPodStatus", name)
		return
	}

	entry := buildPodStatusEntry(r.PodName, executor.Generation, upsertErr)
	// Write the status subresource starting from the object CreateOrUpdate just
	// returned (it carries a fresh resourceVersion) rather than re-reading it
	// through the cache: the informer may not yet observe a just-created object,
	// so an immediate cache Get can return NotFound, which RetryOnConflict does
	// not retry, silently dropping the status. On an optimistic-concurrency
	// conflict we re-fetch and let RetryOnConflict try again.
	statusErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		ps.Status = entry
		updateErr := r.Status().Update(ctx, ps)
		if apierrors.IsConflict(updateErr) {
			if getErr := r.Get(ctx, types.NamespacedName{Name: name, Namespace: r.PodNamespace}, ps); getErr != nil {
				return getErr
			}
		}
		return updateErr
	})
	if statusErr != nil {
		log.Error(statusErr, "Failed to update ExecutorPodStatus status", "executorPodStatus", name)
	}
}

// deletePodStatus removes this pod's ExecutorPodStatus object for the given
// executor name. It is a no-op when the pod identity is unknown or the object
// is already gone.
func (r *ExecutorReconciler) deletePodStatus(ctx context.Context, executorName string) error {
	if r.PodName == "" {
		return nil
	}
	ps := &configv2alpha1.ExecutorPodStatus{
		ObjectMeta: metav1.ObjectMeta{Name: podstatus.PackName(r.PodName, executorName), Namespace: r.PodNamespace},
	}
	return client.IgnoreNotFound(r.Delete(ctx, ps))
}

// setPodOwnerReference best-effort sets the reporting pod as the owner of the
// ExecutorPodStatus so the object is garbage-collected when the pod is deleted.
// Failure to resolve the pod is not fatal: the object is still written, it just
// won't be auto-collected.
func (r *ExecutorReconciler) setPodOwnerReference(ctx context.Context, ps *configv2alpha1.ExecutorPodStatus) {
	log := logf.FromContext(ctx)
	var pod corev1.Pod
	if err := r.Get(ctx, types.NamespacedName{Namespace: r.PodNamespace, Name: r.PodName}, &pod); err != nil {
		log.V(1).Info("could not resolve owning pod for ExecutorPodStatus; skipping owner reference", "pod", r.PodName, "error", err.Error())
		return
	}
	if err := controllerutil.SetOwnerReference(&pod, ps, r.Scheme); err != nil {
		log.V(1).Info("could not set owner reference on ExecutorPodStatus", "pod", r.PodName, "error", err.Error())
	}
}

// updateExecutorStatusDirectly is the single-writer fallback used when the pod
// identity is unknown. The write is wrapped in retry.RetryOnConflict and the
// object is re-fetched on conflict so the update is not silently dropped on an
// HTTP 409.
func (r *ExecutorReconciler) updateExecutorStatusDirectly(ctx context.Context, executor *configv2alpha1.Executor, upsertErr error) {
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
			latest.Status.BriefError = briefError(upsertErr.Error())
		} else {
			latest.Status.Succeeded = true
			latest.Status.Error = ""
			latest.Status.BriefError = ""
		}
		return r.Status().Update(ctx, &latest)
	})
	if retryErr != nil {
		log.Error(retryErr, "Failed to update Executor status", "executor", executor.Name)
	}
}

// buildPodStatusEntry builds the per-pod status entry for the given outcome.
func buildPodStatusEntry(podName string, generation int64, upsertErr error) configv2alpha1.PodStatusEntry {
	now := metav1.NewTime(time.Now())
	entry := configv2alpha1.PodStatusEntry{
		ID:                 podName,
		ObservedGeneration: generation,
		LastTransitionTime: &now,
	}
	if upsertErr != nil {
		entry.Succeeded = false
		entry.Error = upsertErr.Error()
		entry.BriefError = briefError(upsertErr.Error())
	} else {
		entry.Succeeded = true
	}
	return entry
}

// briefError truncates an error message to maxBriefErrorLength characters.
func briefError(msg string) string {
	if len(msg) <= maxBriefErrorLength {
		return msg
	}
	return msg[:maxBriefErrorLength] + "..."
}

// sanitizeLabelValue coerces an arbitrary string into a valid Kubernetes label
// value (<=63 chars, [a-z0-9A-Z] start/end, [a-z0-9A-Z-_.] within). Labels are
// only used for observability/filtering, so a lossy transformation is fine; the
// authoritative pod/executor names live in the object name and status.id.
func sanitizeLabelValue(v string) string {
	if len(v) > 63 {
		v = v[:63]
	}
	b := []byte(v)
	for i, c := range b {
		valid := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'
		if !valid {
			b[i] = '-'
		}
	}
	out := trimNonAlphanumericEnds(string(b))
	if out == "" {
		return unknownLabelValue
	}
	return out
}

func trimNonAlphanumericEnds(s string) string {
	isAlnum := func(c byte) bool {
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
	}
	start := 0
	for start < len(s) && !isAlnum(s[start]) {
		start++
	}
	end := len(s)
	for end > start && !isAlnum(s[end-1]) {
		end--
	}
	return s[start:end]
}
