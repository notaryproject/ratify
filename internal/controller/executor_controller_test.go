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

// revive:disable:dot-imports
package controller

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv2alpha1 "github.com/notaryproject/ratify/v2/api/v2alpha1"
	e "github.com/notaryproject/ratify/v2/internal/executor"
)

var _ = Describe("Executor Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "",
		}
		executor := &configv2alpha1.Executor{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind Executor")
			err := k8sClient.Get(ctx, typeNamespacedName, executor)
			if err != nil && errors.IsNotFound(err) {
				resource := &configv2alpha1.Executor{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "",
					},
					Spec: configv2alpha1.ExecutorSpec{
						Scopes: []string{"example.com"},
						Verifiers: []*configv2alpha1.VerifierOptions{
							{
								Name: mockVerifierName,
								Type: mockVerifierType,
							},
						},
						Stores: []*configv2alpha1.StoreOptions{
							{
								Type: mockStoreType,
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			// // TODO(user): Cleanup logic after each test, like removing the resource instance.
			resource := &configv2alpha1.Executor{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
			GlobalExecutorManager = executorManager{
				opts: make(map[string]e.ScopedOptions),
			}
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &ExecutorReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			updatedExecutor := &configv2alpha1.Executor{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedExecutor)).To(Succeed())
			Expect(updatedExecutor.Status.Succeeded).To(BeTrue())
		})
		It("should handle the case when the resource has been deleted and is not found", func() {
			By("Deleting the existing resource")
			resource := &configv2alpha1.Executor{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, resource)).To(Succeed())
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())

			By("Reconciling after the resource deletion")
			controllerReconciler := &ExecutorReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the resource no longer exists")
			err = k8sClient.Get(ctx, typeNamespacedName, &configv2alpha1.Executor{})
			Expect(errors.IsNotFound(err)).To(BeTrue())

			resource = &configv2alpha1.Executor{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "",
				},
				Spec: configv2alpha1.ExecutorSpec{
					Scopes: []string{"example.com"},
					Verifiers: []*configv2alpha1.VerifierOptions{
						{
							Name: mockVerifierName,
							Type: mockVerifierType,
						},
					},
					Stores: []*configv2alpha1.StoreOptions{
						{
							Type: mockStoreType,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())
		})
		It("should return an error when Client.Get fails with a non-NotFound error", func() {
			By("cancelling the context to simulate an unexpected Client.Get failure")
			cancelledCtx, cancel := context.WithCancel(ctx)
			cancel()

			controllerReconciler := &ExecutorReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(cancelledCtx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			Expect(err).To(HaveOccurred())
			Expect(errors.IsNotFound(err)).To(BeFalse())
		})
		It("should set Status.Succeeded to false when GlobalExecutorManager.UpsertExecutor fails", func() {
			By("reconciling an invalid resource that fails to upsert")

			resource := &configv2alpha1.Executor{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())

			resource = &configv2alpha1.Executor{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "",
				},
				Spec: configv2alpha1.ExecutorSpec{
					Scopes: []string{"example.com"},
					Verifiers: []*configv2alpha1.VerifierOptions{
						{
							Name: mockVerifierName,
							Type: "unsupported-verifier-type", // Intentionally unsupported type to trigger an error
						},
					},
					Stores: []*configv2alpha1.StoreOptions{
						{
							Type: mockStoreType,
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			controllerReconciler := &ExecutorReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			Expect(err).NotTo(HaveOccurred())

			updatedExecutor := &configv2alpha1.Executor{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedExecutor)).To(Succeed())
			// the reconcile should have marked the execution as failed
			Expect(updatedExecutor.Status.Succeeded).To(BeFalse())
			// an error message from the failed upsert should be recorded
			Expect(updatedExecutor.Status.Error).NotTo(BeEmpty())
		})
		It("should update the local executor but not write status on a non-leader replica", func() {
			By("reconciling as a non-leader (leadership not yet acquired)")
			notElected := make(chan struct{})
			controllerReconciler := &ExecutorReconciler{
				Client:  k8sClient,
				Scheme:  k8sClient.Scheme(),
				Elected: notElected,
			}

			result, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying the local executor was still updated on the non-leader")
			Expect(GlobalExecutorManager.GetExecutor()).NotTo(BeNil())

			By("verifying status was not written by the non-leader")
			updatedExecutor := &configv2alpha1.Executor{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedExecutor)).To(Succeed())
			Expect(updatedExecutor.Status.Succeeded).To(BeFalse())

			By("verifying the non-leader requeues so the elected leader writes status later")
			Expect(result.RequeueAfter).To(BeNumerically(">", time.Duration(0)))
		})
		It("should register the controller with the manager", func() {
			mgr, err := ctrl.NewManager(cfg, ctrl.Options{
				Scheme:  k8sClient.Scheme(),
				Metrics: metricsserver.Options{BindAddress: "0"},
			})
			Expect(err).NotTo(HaveOccurred())

			reconciler := &ExecutorReconciler{
				Client: mgr.GetClient(),
				Scheme: mgr.GetScheme(),
			}
			Expect(reconciler.SetupWithManager(mgr)).To(Succeed())
		})
	})
})
