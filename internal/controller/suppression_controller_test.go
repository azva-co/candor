/*
Copyright 2026 Albert Asawaroengchai.

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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
)

var _ = Describe("Suppression Controller", func() {
	Context("When reconciling a resource", func() {
		const (
			resourceName      = "test-resource"
			resourceNamespace = "default"
		)

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: resourceNamespace,
		}
		suppression := &candorv1alpha1.Suppression{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind Suppression")
			err := k8sClient.Get(ctx, typeNamespacedName, suppression)
			if err != nil && errors.IsNotFound(err) {
				resource := &candorv1alpha1.Suppression{
					Name:      resourceName,
					Namespace: resourceNamespace,
					Spec: candorv1alpha1.SuppressionSpec{
						Fingerprint: "fp-test",
						Reason:      "test suppression",
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &candorv1alpha1.Suppression{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance Suppression")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &SuppressionReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			// No expiresAt on this resource, so Reconcile has nothing to compute - this just
			// proves reconciling a real Suppression doesn't error. internal/controller's
			// suppression_expiry_test.go covers the Expired condition logic directly.
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
