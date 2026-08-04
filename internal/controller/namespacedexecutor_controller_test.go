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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv2alpha1 "github.com/notaryproject/ratify/v2/api/v2alpha1"
	e "github.com/notaryproject/ratify/v2/internal/executor"
)

var _ = Describe("NamespacedExecutor Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-namespaced-resource"
		const resourceNamespace = "default"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: resourceNamespace,
		}

		validSpec := func() configv2alpha1.ExecutorSpec {
			return configv2alpha1.ExecutorSpec{
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
			}
		}

		BeforeEach(func() {
			By("creating the custom resource for the Kind NamespacedExecutor")
			executor := &configv2alpha1.NamespacedExecutor{}
			err := k8sClient.Get(ctx, typeNamespacedName, executor)
			if err != nil && errors.IsNotFound(err) {
				resource := &configv2alpha1.NamespacedExecutor{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: resourceNamespace,
					},
					Spec: validSpec(),
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &configv2alpha1.NamespacedExecutor{}
			if err := k8sClient.Get(ctx, typeNamespacedName, resource); err == nil {
				Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
			}
			GlobalExecutorManager = executorManager{
				opts: make(map[string]map[string]e.ScopedOptions),
			}
		})

		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &NamespacedExecutorReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			updatedExecutor := &configv2alpha1.NamespacedExecutor{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedExecutor)).To(Succeed())
			Expect(updatedExecutor.Status.Succeeded).To(BeTrue())
		})

		It("should handle the case when the resource has been deleted and is not found", func() {
			By("Deleting the existing resource")
			resource := &configv2alpha1.NamespacedExecutor{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, resource)).To(Succeed())
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())

			By("Reconciling after the resource deletion")
			controllerReconciler := &NamespacedExecutorReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the resource no longer exists")
			err = k8sClient.Get(ctx, typeNamespacedName, &configv2alpha1.NamespacedExecutor{})
			Expect(errors.IsNotFound(err)).To(BeTrue())
		})

		It("should return an error when Client.Get fails with a non-NotFound error", func() {
			By("cancelling the context to simulate an unexpected Client.Get failure")
			cancelledCtx, cancel := context.WithCancel(ctx)
			cancel()

			controllerReconciler := &NamespacedExecutorReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(cancelledCtx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			Expect(err).To(HaveOccurred())
			Expect(errors.IsNotFound(err)).To(BeFalse())
		})

		It("should set Status.Succeeded to false when upsert fails", func() {
			By("reconciling an invalid resource that fails to upsert")

			resource := &configv2alpha1.NamespacedExecutor{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, resource)).To(Succeed())
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())

			spec := validSpec()
			spec.Verifiers[0].Type = "unsupported-verifier-type" // Intentionally unsupported to trigger an error
			resource = &configv2alpha1.NamespacedExecutor{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: resourceNamespace,
				},
				Spec: spec,
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			controllerReconciler := &NamespacedExecutorReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			updatedExecutor := &configv2alpha1.NamespacedExecutor{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedExecutor)).To(Succeed())
			Expect(updatedExecutor.Status.Succeeded).To(BeFalse())
			Expect(updatedExecutor.Status.Error).NotTo(BeEmpty())
		})
	})
})
