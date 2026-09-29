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

var _ = Describe("Finding Controller", func() {
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
		finding := &candorv1alpha1.Finding{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind Finding")
			err := k8sClient.Get(ctx, typeNamespacedName, finding)
			if err != nil && errors.IsNotFound(err) {
				resource := &candorv1alpha1.Finding{
					Name:      resourceName,
					Namespace: resourceNamespace,
					Spec: candorv1alpha1.FindingSpec{
						Source: candorv1alpha1.FindingSource{
							Provider: testProvider,
							Kind:     testKind,
							Name:     testResourceName,
							RefKind:  testRefKindVulnReport,
							RefName:  "api-report",
						},
						Severity: "HIGH",
						Summary:  "test finding",
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &candorv1alpha1.Finding{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance Finding")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &FindingReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			// FindingReconciler is a no-op for now (see finding_controller.go) - this just proves
			// reconciling a real Finding doesn't error, which is all there is to assert until a
			// later slice gives it actual work to do.
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
