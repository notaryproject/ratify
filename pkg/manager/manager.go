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
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	"github.com/ratify-project/ratify/config"
	"github.com/ratify-project/ratify/httpserver"
	"github.com/ratify-project/ratify/pkg/featureflag"
	_ "github.com/ratify-project/ratify/pkg/policyprovider/configpolicy" // register config policy provider
	_ "github.com/ratify-project/ratify/pkg/policyprovider/regopolicy"   // register rego policy provider
	_ "github.com/ratify-project/ratify/pkg/referrerstore/oras"          // register ORAS referrer store
	"github.com/ratify-project/ratify/pkg/utils"
	_ "github.com/ratify-project/ratify/pkg/verifier/notation" // register notation verifier
	"github.com/sirupsen/logrus"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // import additional authentication methods

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"

	configv1alpha1 "github.com/ratify-project/ratify/api/v1alpha1"
	configv1beta1 "github.com/ratify-project/ratify/api/v1beta1"
	ctxUtils "github.com/ratify-project/ratify/internal/context"
	"github.com/ratify-project/ratify/pkg/controllers"
	"github.com/ratify-project/ratify/pkg/controllers/clusterresource"
	"github.com/ratify-project/ratify/pkg/controllers/namespaceresource"
	ef "github.com/ratify-project/ratify/pkg/executor/core"
	//+kubebuilder:scaffold:imports
)

const (
	caOrganization = "Ratify"
	certDir        = "/usr/local/tls"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = logrus.WithField("name", "setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(configv1alpha1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
	utilruntime.Must(configv1beta1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func StartServer(httpServerAddress, configFilePath, certDirectory string, caCertFiles []string, cacheTTL time.Duration, metricsEnabled bool, metricsType string, metricsPort int, certRotatorReady chan struct{}) {
	logrus.Info("initializing executor with config file at default config path")

	cf, err := config.Load(configFilePath)
	if err != nil {
		logrus.Errorf("server start failed %v", fmt.Errorf("error loading config %w", err))
		os.Exit(1)
	}
	config.CRLConf = cf.CRLConfig
	// initialize server
	server, err := httpserver.NewServer(context.Background(), httpServerAddress, func(ctx context.Context) *ef.Executor {
		namespace := ctxUtils.GetNamespace(ctx)

		activeVerifiers := controllers.NamespacedVerifiers.GetVerifiers(namespace)
		activePolicyEnforcer := controllers.NamespacedPolicies.GetPolicy(namespace)
		activeStores := controllers.NamespacedStores.GetStores(namespace)

		// return executor with latest configuration
		executor := ef.Executor{
			Verifiers:      activeVerifiers,
			ReferrerStores: activeStores,
			PolicyEnforcer: activePolicyEnforcer,
			Config:         &cf.ExecutorConfig,
		}
		return &executor
	}, certDirectory, caCertFiles, cacheTTL, metricsEnabled, metricsType, metricsPort)

	if err != nil {
		logrus.Errorf("initialize server failed with error %v, exiting..", err)
		os.Exit(1)
	}
	logrus.Infof("starting server at %s", httpServerAddress)
	if err := server.Run(certRotatorReady); err != nil {
		logrus.Errorf("starting server failed with error %v, exiting..", err)
		os.Exit(1)
	}
}

func StartManager(certRotatorReady chan struct{}, probeAddr string) {
	var enableLeaderElection bool

	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.Parse()

	logrusSink := controllers.NewLogrusSink(logrus.StandardLogger())
	ctrl.SetLogger(logr.New(logrusSink))
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "1a306109.github.com/ratify-project/ratify",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	setupLog.Debugf("setting up probeAddr at %s", probeAddr)

	// Make sure certs are generated and valid if cert rotation is enabled.
	if featureflag.CertRotation.Enabled {
		// Make sure TLS cert watcher is already set up.
		if certRotatorReady == nil {
			setupLog.Error(err, "to use cert rotation, you must provide a channel to signal when the TLS watcher is ready")
			os.Exit(1)
		}
		setupLog.Info("setting up cert rotation")

		keyUsages := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		webhooks := []rotator.WebhookInfo{
			{
				Name: "ratify-mutation-provider",
				Type: rotator.ExternalDataProvider,
			},
			{
				Name: "ratify-provider",
				Type: rotator.ExternalDataProvider,
			},
		}
		namespace := utils.GetNamespace()
		serviceName := utils.GetServiceName()

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
			setupLog.Error(err, "Unable to set up cert rotation")
			os.Exit(1)
		}
	} else {
		close(certRotatorReady)
	}

	if err = (&clusterresource.VerifierReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Cluster Verifier")
		os.Exit(1)
	}
	if err = (&namespaceresource.VerifierReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Namespaced Verifier")
		os.Exit(1)
	}
	if err = (&clusterresource.StoreReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Store")
		os.Exit(1)
	}
	if err = (&namespaceresource.StoreReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Namespaced Store")
		os.Exit(1)
	}
	if err = (&namespaceresource.CertificateStoreReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Namespaced Certificate Store")
		os.Exit(1)
	}
	if err = (&namespaceresource.PolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Namespaced Policy")
		os.Exit(1)
	}
	if err = (&clusterresource.PolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Policy")
		os.Exit(1)
	}
	if err = (&clusterresource.KeyManagementProviderReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Cluster Key Management Provider")
		os.Exit(1)
	}
	if err = (&namespaceresource.KeyManagementProviderReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Namespaced Key Management Provider")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
