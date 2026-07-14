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

package namespaceresource

import (
	"context"
	"fmt"

	configv1beta1 "github.com/notaryproject/ratify/v2/api/v1beta1"
	re "github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/internal/constants"
	"github.com/notaryproject/ratify/v2/pkg/controllers"
	"github.com/notaryproject/ratify/v2/pkg/controllers/utils"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// PolicyReconciler reconciles a Policy object
type PolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=config.ratify.deislabs.io,resources=namespacedpolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=config.ratify.deislabs.io,resources=namespacedpolicies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=config.ratify.deislabs.io,resources=namespacedpolicies/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *PolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	policyLogger := logrus.WithContext(ctx)

	var policy configv1beta1.NamespacedPolicy
	var resource = req.Name
	policyLogger.Infof("Reconciling Namespaced Policy %s", resource)

	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		if apierrors.IsNotFound(err) {
			policyLogger.Infof("delete event detected, removing policy %s", resource)
			controllers.NamespacedPolicies.DeletePolicy(req.Namespace, resource)
		} else {
			policyLogger.Error("failed to get Policy: ", err)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if resource != constants.RatifyPolicy {
		err := re.ErrorCodeConfigInvalid.WithDetail(fmt.Sprintf("metadata.name must be ratify-policy, got %s", resource))
		policyLogger.Error(err)
		writePolicyStatus(ctx, r, &policy, policyLogger, false, &err)
		return ctrl.Result{}, nil
	}

	if err := policyAddOrReplace(policy.Spec, req.Namespace); err != nil {
		policyErr := re.ErrorCodePluginInitFailure.WithError(err).WithDetail("Unable to create policy from policy CR")
		policyLogger.Error(policyErr)
		writePolicyStatus(ctx, r, &policy, policyLogger, false, &policyErr)
		return ctrl.Result{}, policyErr
	}

	writePolicyStatus(ctx, r, &policy, policyLogger, true, nil)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&configv1beta1.NamespacedPolicy{}).
		Complete(r)
}

func policyAddOrReplace(spec configv1beta1.NamespacedPolicySpec, namespace string) error {
	policyEnforcer, err := utils.SpecToPolicyEnforcer(spec.Parameters.Raw, spec.Type)
	if err != nil {
		return err
	}

	controllers.NamespacedPolicies.AddPolicy(namespace, constants.RatifyPolicy, policyEnforcer)
	return nil
}

func writePolicyStatus(ctx context.Context, r client.StatusClient, policy *configv1beta1.NamespacedPolicy, logger *logrus.Entry, isSuccess bool, err *re.Error) {
	if isSuccess {
		updatePolicySuccessStatus(policy)
	} else {
		updatePolicyErrorStatus(policy, err)
	}
	if statusErr := r.Status().Update(ctx, policy); statusErr != nil {
		logger.Error(statusErr, ", unable to update policy error status")
	}
}

func updatePolicySuccessStatus(policy *configv1beta1.NamespacedPolicy) {
	policy.Status.IsSuccess = true
	policy.Status.Error = ""
	policy.Status.BriefError = ""
}

func updatePolicyErrorStatus(policy *configv1beta1.NamespacedPolicy, err *re.Error) {
	policy.Status.IsSuccess = false
	policy.Status.Error = err.Error()
	policy.Status.BriefError = err.GetConciseError(constants.MaxBriefErrLength)
}
