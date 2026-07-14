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

package clusterresource

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1beta1 "github.com/notaryproject/ratify/v2/api/v1beta1"
	re "github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/internal/constants"
	"github.com/notaryproject/ratify/v2/pkg/controllers"
	"github.com/notaryproject/ratify/v2/pkg/controllers/utils"
	"github.com/sirupsen/logrus"
)

// StoreReconciler reconciles a Store object
type StoreReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=config.ratify.deislabs.io,resources=stores,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=config.ratify.deislabs.io,resources=stores/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=config.ratify.deislabs.io,resources=stores/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *StoreReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	storeLogger := logrus.WithContext(ctx)

	var store configv1beta1.Store
	var resource = req.Name
	storeLogger.Infof("reconciling cluster store '%v'", resource)

	if err := r.Get(ctx, req.NamespacedName, &store); err != nil {
		if apierrors.IsNotFound(err) {
			storeLogger.Infof("deletion detected, removing store %v", req.Name)
			controllers.NamespacedStores.DeleteStore(constants.EmptyNamespace, resource)
		} else {
			storeLogger.Error(err, "unable to fetch store")
		}

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := storeAddOrReplace(store.Spec, resource); err != nil {
		storeErr := re.ErrorCodeReferrerStoreFailure.WithError(err).WithDetail("Unable to create store from store CR")
		storeLogger.Error(err)
		writeStoreStatus(ctx, r, &store, storeLogger, false, &storeErr)
		return ctrl.Result{}, storeErr
	}

	writeStoreStatus(ctx, r, &store, storeLogger, true, nil)

	// returning empty result and no error to indicate we’ve successfully reconciled this object
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *StoreReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&configv1beta1.Store{}).
		Complete(r)
}

// Creates a store reference from CRD spec and add store to map
func storeAddOrReplace(spec configv1beta1.StoreSpec, fullname string) error {
	storeConfig, err := utils.CreateStoreConfig(spec.Parameters.Raw, spec.Name, spec.Source)
	if err != nil {
		return err
	}

	return utils.UpsertStoreMap(spec.Version, spec.Address, fullname, constants.EmptyNamespace, storeConfig)
}

func writeStoreStatus(ctx context.Context, r client.StatusClient, store *configv1beta1.Store, logger *logrus.Entry, isSuccess bool, err *re.Error) {
	if isSuccess {
		store.Status.IsSuccess = true
		store.Status.Error = ""
		store.Status.BriefError = ""
	} else {
		store.Status.IsSuccess = false
		store.Status.Error = err.Error()
		store.Status.BriefError = err.GetConciseError(constants.MaxBriefErrLength)
	}

	if statusErr := r.Status().Update(ctx, store); statusErr != nil {
		logger.Error(statusErr, ",unable to update store error status")
	}
}
