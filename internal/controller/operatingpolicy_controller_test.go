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
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
)

// OperatingPolicy is cluster-scoped (see its own doc comment) - unlike every other Describe block
// in this package, there's deliberately no Namespace field anywhere below.
var _ = Describe("OperatingPolicy Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()
		typeNamespacedName := types.NamespacedName{Name: resourceName}
		operatingpolicy := &candorv1alpha1.OperatingPolicy{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind OperatingPolicy")
			err := k8sClient.Get(ctx, typeNamespacedName, operatingpolicy)
			if err != nil && errors.IsNotFound(err) {
				resource := &candorv1alpha1.OperatingPolicy{
					Name: resourceName,
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &candorv1alpha1.OperatingPolicy{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance OperatingPolicy")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})

		It("sets Ready=True when it's the only OperatingPolicy in the cluster", func() {
			By("Reconciling the created resource")
			controllerReconciler := &OperatingPolicyReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Recorder: record.NewFakeRecorder(10),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			got := &candorv1alpha1.OperatingPolicy{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, got)).To(Succeed())
			cond := findCondition(got.Status.Conditions, "Ready")
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionTrue))
		})
	})
})
