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
	"encoding/json"
	"fmt"

	re "github.com/notaryproject/ratify/v2/errors"
	"github.com/notaryproject/ratify/v2/internal/constants"
	cutils "github.com/notaryproject/ratify/v2/pkg/controllers/utils"
	kmp "github.com/notaryproject/ratify/v2/pkg/keymanagementprovider"
	_ "github.com/notaryproject/ratify/v2/pkg/keymanagementprovider/azurekeyvault" // register azure key vault key management provider
	_ "github.com/notaryproject/ratify/v2/pkg/keymanagementprovider/inline"        // register inline key management provider
	"github.com/notaryproject/ratify/v2/pkg/keymanagementprovider/refresh"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	configv1beta1 "github.com/notaryproject/ratify/v2/api/v1beta1"
)

// KeyManagementProviderReconciler reconciles a KeyManagementProvider object
type KeyManagementProviderReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func (r *KeyManagementProviderReconciler) ReconcileWithType(ctx context.Context, req ctrl.Request, refresherType string) (ctrl.Result, error) {
	logger := logrus.WithContext(ctx)

	var keyManagementProvider configv1beta1.KeyManagementProvider

	resource := req.Name

	logger.Infof("reconciling cluster key management provider '%v'", resource)

	if err := r.Get(ctx, req.NamespacedName, &keyManagementProvider); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Infof("deletion detected, removing key management provider %v", resource)
			kmp.DeleteResourceFromMap(resource)
		} else {
			logger.Error(err, "unable to fetch key management provider")
		}

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	lastFetchedTime := metav1.Now()

	// get certificate store list to check if certificate store is configured
	// TODO: remove check in v2.0.0+
	var certificateStoreList configv1beta1.CertificateStoreList
	if err := r.List(ctx, &certificateStoreList); err != nil {
		logger.Error(err, "unable to list certificate stores")
		return ctrl.Result{}, err
	}

	if len(certificateStoreList.Items) > 0 {
		// Note: for backwards compatibility in upgrade scenarios, Ratify will only log a warning statement.
		logger.Warn("Certificate Store already exists. Key management provider and certificate store should not be configured together. Please migrate to key management provider and delete certificate store.")
	}

	provider, err := cutils.SpecToKeyManagementProvider(keyManagementProvider.Spec.Parameters.Raw, keyManagementProvider.Spec.Type, resource)
	if err != nil {
		kmpErr := re.ErrorCodeKeyManagementProviderFailure.WithError(err).WithDetail("Failed to create key management provider from CR")

		kmp.SetCertificateError(resource, kmpErr)
		kmp.SetKeyError(resource, kmpErr)
		writeKMProviderStatus(ctx, r, &keyManagementProvider, logger, false, &kmpErr, lastFetchedTime, nil)
		return ctrl.Result{}, kmpErr
	}

	refresherConfig := refresh.RefresherConfig{
		RefresherType:           refresherType,
		Provider:                provider,
		ProviderType:            keyManagementProvider.Spec.Type,
		ProviderRefreshInterval: keyManagementProvider.Spec.RefreshInterval,
		Resource:                resource,
	}

	refresher, err := refresh.CreateRefresherFromConfig(refresherConfig)
	if err != nil {
		kmpErr := re.ErrorCodeKeyManagementProviderFailure.WithError(err).WithDetail("Failed to create refresher from config")
		kmp.SetCertificateError(resource, kmpErr)
		kmp.SetKeyError(resource, kmpErr)
		writeKMProviderStatus(ctx, r, &keyManagementProvider, logger, false, &kmpErr, lastFetchedTime, nil)
		return ctrl.Result{}, kmpErr
	}

	err = refresher.Refresh(ctx)
	if err != nil {
		kmpErr := re.ErrorCodeKeyManagementProviderFailure.WithError(err).WithDetail("Failed to refresh key management provider")
		writeKMProviderStatus(ctx, r, &keyManagementProvider, logger, false, &kmpErr, lastFetchedTime, nil)
		return ctrl.Result{}, kmpErr
	}

	result, ok := refresher.GetResult().(ctrl.Result)
	if !ok {
		kmpErr := re.ErrorCodeKeyManagementProviderFailure.WithError(err).WithDetail("Failed to get result from refresher")
		writeKMProviderStatus(ctx, r, &keyManagementProvider, logger, false, &kmpErr, lastFetchedTime, nil)
		return ctrl.Result{}, fmt.Errorf("unexpected type returned from GetResult: %T", refresher.GetResult())
	}

	status, ok := refresher.GetStatus().(kmp.KeyManagementProviderStatus)
	if !ok {
		kmpErr := re.ErrorCodeKeyManagementProviderFailure.WithError(err).WithDetail("Failed to get status from refresher")
		writeKMProviderStatus(ctx, r, &keyManagementProvider, logger, false, &kmpErr, lastFetchedTime, nil)
		return ctrl.Result{}, fmt.Errorf("unexpected type returned from GetStatus: %T", refresher.GetStatus())
	}

	writeKMProviderStatus(ctx, r, &keyManagementProvider, logger, true, nil, lastFetchedTime, status)

	return result, nil
}

// +kubebuilder:rbac:groups=config.ratify.deislabs.io,resources=keymanagementproviders,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=config.ratify.deislabs.io,resources=keymanagementproviders/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=config.ratify.deislabs.io,resources=keymanagementproviders/finalizers,verbs=update
func (r *KeyManagementProviderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return r.ReconcileWithType(ctx, req, refresh.KubeRefresherType)
}

// SetupWithManager sets up the controller with the Manager.
func (r *KeyManagementProviderReconciler) SetupWithManager(mgr ctrl.Manager) error {
	pred := predicate.GenerationChangedPredicate{}

	// status updates will trigger a reconcile event
	// if there are no changes to spec of CRD, this event should be filtered out by using the predicate
	// see more discussions at https://github.com/kubernetes-sigs/kubebuilder/issues/618
	return ctrl.NewControllerManagedBy(mgr).
		For(&configv1beta1.KeyManagementProvider{}).WithEventFilter(pred).
		Complete(r)
}

func writeKMProviderStatus(ctx context.Context, r client.StatusClient, keyManagementProvider *configv1beta1.KeyManagementProvider, logger *logrus.Entry, isSuccess bool, err *re.Error, operationTime metav1.Time, kmProviderStatus kmp.KeyManagementProviderStatus) {
	if isSuccess {
		updateKMProviderSuccessStatus(keyManagementProvider, &operationTime, kmProviderStatus)
	} else {
		updateKMProviderErrorStatus(keyManagementProvider, err, &operationTime)
	}
	if statusErr := r.Status().Update(ctx, keyManagementProvider); statusErr != nil {
		logger.Error(statusErr, ",unable to update key management provider error status")
	}
}

// updateKMProviderErrorStatus updates the key management provider status with error, brief error and last fetched time
func updateKMProviderErrorStatus(keyManagementProvider *configv1beta1.KeyManagementProvider, err *re.Error, operationTime *metav1.Time) {
	keyManagementProvider.Status.IsSuccess = false
	keyManagementProvider.Status.Error = err.Error()
	keyManagementProvider.Status.BriefError = err.GetConciseError(constants.MaxBriefErrLength)
	keyManagementProvider.Status.LastFetchedTime = operationTime
}

// updateKMProviderSuccessStatus updates the key management provider status if status argument is non nil
// Success status includes last fetched time and other provider-specific properties
func updateKMProviderSuccessStatus(keyManagementProvider *configv1beta1.KeyManagementProvider, lastOperationTime *metav1.Time, kmProviderStatus kmp.KeyManagementProviderStatus) {
	keyManagementProvider.Status.IsSuccess = true
	keyManagementProvider.Status.Error = ""
	keyManagementProvider.Status.BriefError = ""
	keyManagementProvider.Status.LastFetchedTime = lastOperationTime

	if kmProviderStatus != nil {
		jsonString, _ := json.Marshal(kmProviderStatus)

		raw := runtime.RawExtension{
			Raw: jsonString,
		}
		keyManagementProvider.Status.Properties = raw
	}
}
