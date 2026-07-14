// Copyright The Ratify Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package namespaceresource

import (
	"context"
	"encoding/json"
	"fmt"

	configv1beta1 "github.com/notaryproject/ratify/v2/api/v1beta1"
	"github.com/notaryproject/ratify/v2/internal/constants"
	"github.com/notaryproject/ratify/v2/pkg/certificateprovider"
	_ "github.com/notaryproject/ratify/v2/pkg/certificateprovider/azurekeyvault" // register azure keyvault certificate provider
	_ "github.com/notaryproject/ratify/v2/pkg/certificateprovider/inline"        // register inline certificate provider
	"github.com/notaryproject/ratify/v2/pkg/controllers"
	"github.com/notaryproject/ratify/v2/pkg/utils"

	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// CertificateStoreReconciler reconciles a CertificateStore object
type CertificateStoreReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=config.ratify.deislabs.io,resources=certificatestores,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=config.ratify.deislabs.io,resources=certificatestores/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=config.ratify.deislabs.io,resources=certificatestores/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// the CertificateStore object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *CertificateStoreReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logrus.WithContext(ctx)

	var resource = req.String()
	var certStore configv1beta1.CertificateStore

	logger.Infof("reconciling certificate store '%v'", resource)

	if err := r.Get(ctx, req.NamespacedName, &certStore); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Infof("deletion detected, removing certificate store %v", resource)
			controllers.NamespacedCertStores.DeleteStore(resource)
		} else {
			logger.Error(err, "unable to fetch certificate store")
		}

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	lastFetchedTime := metav1.Now()
	isFetchSuccessful := false

	// get cert provider attributes
	attributes, err := getCertStoreConfig(certStore.Spec)

	if err != nil {
		writeCertStoreStatus(ctx, r, certStore, logger, isFetchSuccessful, err.Error(), lastFetchedTime, nil)
		return ctrl.Result{}, err
	}

	provider, err := getCertificateProvider(certificateprovider.GetCertificateProviders(), certStore.Spec.Provider)
	if err != nil {
		writeCertStoreStatus(ctx, r, certStore, logger, isFetchSuccessful, err.Error(), lastFetchedTime, nil)
		return ctrl.Result{}, err
	}

	certificates, certAttributes, err := provider.GetCertificates(ctx, attributes)
	if err != nil {
		writeCertStoreStatus(ctx, r, certStore, logger, isFetchSuccessful, err.Error(), lastFetchedTime, nil)
		return ctrl.Result{}, fmt.Errorf("error fetching certificates in store %v with %v provider, error: %w", resource, certStore.Spec.Provider, err)
	}

	controllers.NamespacedCertStores.AddStore(resource, certificates)
	isFetchSuccessful = true
	emptyErrorString := ""
	writeCertStoreStatus(ctx, r, certStore, logger, isFetchSuccessful, emptyErrorString, lastFetchedTime, certAttributes)

	logger.Infof("%v certificates fetched for certificate store %v", len(certificates), resource)

	// returning empty result and no error to indicate we’ve successfully reconciled this object
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateStoreReconciler) SetupWithManager(mgr ctrl.Manager) error {
	pred := predicate.GenerationChangedPredicate{}

	// status updates will trigger a reconcile event
	// if there are no changes to spec of CRD, this event should be filtered out by using the predicate
	// see more discussions at https://github.com/kubernetes-sigs/kubebuilder/issues/618
	return ctrl.NewControllerManagedBy(mgr).
		For(&configv1beta1.CertificateStore{}).WithEventFilter(pred).
		Complete(r)
}

func getCertStoreConfig(spec configv1beta1.CertificateStoreSpec) (map[string]string, error) {
	attributes := map[string]string{}

	if string(spec.Parameters.Raw) == "" {
		return nil, fmt.Errorf("received empty parameters")
	}

	if err := json.Unmarshal(spec.Parameters.Raw, &attributes); err != nil {
		logrus.Error(err, ",unable to decode cert store parameters", "Parameters.Raw", spec.Parameters.Raw)
		return attributes, err
	}

	return attributes, nil
}

func writeCertStoreStatus(ctx context.Context, r *CertificateStoreReconciler, certStore configv1beta1.CertificateStore, logger *logrus.Entry, isSuccess bool, errorString string, operationTime metav1.Time, certStatus certificateprovider.CertificatesStatus) {
	if isSuccess {
		updateSuccessStatus(&certStore, &operationTime, certStatus)
	} else {
		updateErrorStatus(&certStore, errorString, &operationTime)
	}
	if statusErr := r.Status().Update(ctx, &certStore); statusErr != nil {
		logger.Error(statusErr, ",unable to update certificate store error status")
	}
}

func updateErrorStatus(certStore *configv1beta1.CertificateStore, errorString string, operationTime *metav1.Time) {
	// truncate brief error string to maxBriefErrLength
	briefErr := errorString
	if len(errorString) > constants.MaxBriefErrLength {
		briefErr = fmt.Sprintf("%s...", errorString[:constants.MaxBriefErrLength])
	}
	certStore.Status.IsSuccess = false
	certStore.Status.Error = errorString
	certStore.Status.BriefError = briefErr
	certStore.Status.LastFetchedTime = operationTime
}

func updateSuccessStatus(certStore *configv1beta1.CertificateStore, lastOperationTime *metav1.Time, certStatus certificateprovider.CertificatesStatus) {
	certStore.Status.IsSuccess = true
	certStore.Status.Error = ""
	certStore.Status.BriefError = ""
	certStore.Status.LastFetchedTime = lastOperationTime

	if certStatus != nil {
		jsonString, _ := json.Marshal(certStatus)

		raw := runtime.RawExtension{
			Raw: jsonString,
		}
		certStore.Status.Properties = raw
	}
}

// given the name of the target provider, returns the provider from the providers map
func getCertificateProvider(providers map[string]certificateprovider.CertificateProvider, providerName string) (certificateprovider.CertificateProvider, error) {
	providerName = utils.TrimSpaceAndToLower(providerName)
	provider, registered := providers[providerName]
	if !registered {
		return nil, fmt.Errorf("unknown provider value '%v' defined", provider)
	}
	return provider, nil
}
