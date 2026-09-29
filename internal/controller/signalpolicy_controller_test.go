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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
)

var _ = Describe("SignalPolicy Controller", func() {
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
		signalpolicy := &candorv1alpha1.SignalPolicy{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind SignalPolicy")
			err := k8sClient.Get(ctx, typeNamespacedName, signalpolicy)
			if err != nil && errors.IsNotFound(err) {
				resource := &candorv1alpha1.SignalPolicy{
					Name:      resourceName,
					Namespace: resourceNamespace,
					Spec: candorv1alpha1.SignalPolicySpec{
						Providers:   []string{testProvider},
						MinSeverity: "HIGH",
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &candorv1alpha1.SignalPolicy{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance SignalPolicy")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &SignalPolicyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("setting a Ready condition since \"trivy\" is a known provider")
			updated := &candorv1alpha1.SignalPolicy{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())
			cond := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionTrue))
		})
	})

	Context("When webhook is enabled without a WebhookReceiver", func() {
		// Regression test: the webhook receiver (internal/provider/webhook) fails closed
		// identically whether a SignalPolicy doesn't exist or exists without a WebhookReceiver
		// configured - Ready must say so plainly, since the receiver's own response can't tell
		// the two apart (deliberate, for enumeration-avoidance) and this condition is the only
		// place an operator can.
		const name = "webhook-no-receiver"
		const resourceNamespace = "default"

		AfterEach(func() {
			resource := &candorv1alpha1.SignalPolicy{}
			if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: name, Namespace: resourceNamespace}, resource); err == nil {
				Expect(k8sClient.Delete(context.Background(), resource)).To(Succeed())
			}
		})

		It("reports Ready=False, not Ready=True", func() {
			ctx := context.Background()
			resource := &candorv1alpha1.SignalPolicy{
				Name:      name,
				Namespace: resourceNamespace,
				Spec:      candorv1alpha1.SignalPolicySpec{Providers: []string{"webhook"}},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			controllerReconciler := &SignalPolicyReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				Name: name, Namespace: resourceNamespace,
			})
			Expect(err).NotTo(HaveOccurred())

			updated := &candorv1alpha1.SignalPolicy{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: resourceNamespace}, updated)).To(Succeed())
			cond := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal("WebhookReceiverNotConfigured"))
		})
	})

	Context("When a WebhookReceiver is configured but webhook isn't in providers", func() {
		// The opposite misconfiguration, same failure class: the receiver only checks
		// WebhookReceiver != nil, so it authenticates successfully and calls Ingest - which then
		// filters every signal because "webhook" was never enabled. Ready must catch this
		// direction too, not just the one already covered above.
		const name = "webhookreceiver-not-enabled"
		const resourceNamespace = "default"

		AfterEach(func() {
			resource := &candorv1alpha1.SignalPolicy{}
			if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: name, Namespace: resourceNamespace}, resource); err == nil {
				Expect(k8sClient.Delete(context.Background(), resource)).To(Succeed())
			}
		})

		It("reports Ready=False, not Ready=True", func() {
			ctx := context.Background()
			resource := &candorv1alpha1.SignalPolicy{
				Name:      name,
				Namespace: resourceNamespace,
				Spec: candorv1alpha1.SignalPolicySpec{
					Providers:       []string{testProvider},
					WebhookReceiver: &candorv1alpha1.WebhookReceiver{SecretRef: corev1.LocalObjectReference{Name: "webhook-secret"}},
				},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			controllerReconciler := &SignalPolicyReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				Name: name, Namespace: resourceNamespace,
			})
			Expect(err).NotTo(HaveOccurred())

			updated := &candorv1alpha1.SignalPolicy{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: resourceNamespace}, updated)).To(Succeed())
			cond := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal("WebhookReceiverConfiguredButNotEnabled"))
		})
	})

	Context("When a policy has two independent problems at once", func() {
		// Regression test: a switch that stops at the first matching case would report only the
		// unknown-provider problem and silently hide the webhook misconfiguration until the first
		// is fixed and the policy reconciles again - both must be visible in the same pass.
		const name = "two-problems-at-once"
		const resourceNamespace = "default"

		AfterEach(func() {
			resource := &candorv1alpha1.SignalPolicy{}
			if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: name, Namespace: resourceNamespace}, resource); err == nil {
				Expect(k8sClient.Delete(context.Background(), resource)).To(Succeed())
			}
		})

		It("reports both problems, not just the first one found", func() {
			ctx := context.Background()
			resource := &candorv1alpha1.SignalPolicy{
				Name:      name,
				Namespace: resourceNamespace,
				Spec: candorv1alpha1.SignalPolicySpec{
					Providers: []string{"webhook", "not-a-real-provider"},
				},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			controllerReconciler := &SignalPolicyReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				Name: name, Namespace: resourceNamespace,
			})
			Expect(err).NotTo(HaveOccurred())

			updated := &candorv1alpha1.SignalPolicy{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: resourceNamespace}, updated)).To(Succeed())
			cond := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal("Misconfigured"))
			Expect(cond.Message).To(ContainSubstring("not-a-real-provider"))
			Expect(cond.Message).To(ContainSubstring("webhookReceiver is not set"))
		})
	})
})
