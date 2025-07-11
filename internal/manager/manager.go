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

package manager

import (
	"crypto/x509"
	"fmt"
	"os"

	"github.com/bombsimon/logrusr/v4"
	"github.com/notaryproject/ratify/v2/api/v2alpha1"
	"github.com/notaryproject/ratify/v2/internal/controller"
	"github.com/notaryproject/ratify/v2/internal/pod"
	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	caOrganization = "Ratify"
	certDir        = "/usr/local/tls"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("manager-setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v2alpha1.AddToScheme(scheme))
}

// StartManager creates a new Manager which is responsible for creating
// Controllers.
func StartManager(certRotatorReady chan struct{}, disableMutation bool, disableCRDManager bool) {
	ctrl.SetLogger(logrusr.New(logrus.StandardLogger()))
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
	})
	if err != nil {
		setupLog.Error(err, "could not create ratify manager")
		os.Exit(1)
	}

	setupCertRotator(certRotatorReady, mgr, disableMutation)
	setupCRDControllers(mgr, disableCRDManager)

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "could not start manager")
		os.Exit(1)
	}
}

func setupCertRotator(certRotatorReady chan struct{}, mgr ctrl.Manager, disableMutation bool) {
	if certRotatorReady == nil {
		setupLog.Info("cert rotator is disabled")
		return
	}

	setupLog.Info("setting up cert rotation")
	keyUsages := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	webhooks := []rotator.WebhookInfo{
		{
			Name: "ratify-gatekeeper-provider",
			Type: rotator.ExternalDataProvider,
		},
	}
	if !disableMutation {
		webhooks = append(webhooks, rotator.WebhookInfo{
			Name: "ratify-gatekeeper-mutation-provider",
			Type: rotator.ExternalDataProvider,
		})
	}

	namespace := pod.Namespace()
	serviceName := pod.ServiceName()

	if err := rotator.AddRotator(mgr, &rotator.CertRotator{
		SecretKey: types.NamespacedName{
			Namespace: namespace,
			Name:      fmt.Sprintf("%s-tls", serviceName),
		},
		CertDir:        certDir,
		CAName:         fmt.Sprintf("%s.%s", serviceName, namespace),
		CAOrganization: caOrganization,
		DNSName:        fmt.Sprintf("%s.%s", serviceName, namespace),
		IsReady:        certRotatorReady,
		Webhooks:       webhooks,
		ExtKeyUsages:   &keyUsages,
	}); err != nil {
		setupLog.Error(err, "unable to set up cert rotation")
		os.Exit(1)
	}
}

func setupCRDControllers(mgr ctrl.Manager, disableCRDManager bool) {
	if disableCRDManager {
		setupLog.Info("CRD manager is disabled")
		return
	}

	setupLog.Info("setting up CRD controllers")
	if err := (&controller.ExecutorReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "could not set up Executor reconciler")
		os.Exit(1)
	}
}
