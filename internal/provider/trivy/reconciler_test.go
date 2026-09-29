package trivy

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
	"github.com/azva-co/candor/internal/provider"
	"github.com/azva-co/candor/internal/signal"
)

const testPolicyName = "policy"

var _ = Describe("Trivy provider reconciler", func() {
	var namespace string

	BeforeEach(func() {
		// time.Now().UnixNano(), not GinkgoRandomSeed() - the seed is fixed for the whole run, so
		// every spec would otherwise collide on the same namespace name.
		namespace = fmt.Sprintf("test-%d", time.Now().UnixNano())
		ns := &corev1.Namespace{Name: namespace}
		Expect(k8sClient.Create(ctx, ns)).To(Succeed())
		DeferCleanup(func() {
			Expect(k8sClient.Delete(ctx, ns)).To(Succeed())
		})
	})

	newVulnReport := func(name string, criticalCount int64) *unstructured.Unstructured {
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(GroupVersionKind)
		u.SetName(name)
		u.SetNamespace(namespace)
		u.SetLabels(map[string]string{
			labelResourceKind: "Deployment",
			labelResourceName: "api",
		})
		Expect(unstructured.SetNestedField(u.Object, map[string]any{
			"criticalCount": criticalCount, "highCount": int64(0), "mediumCount": int64(0),
			"lowCount": int64(0), "unknownCount": int64(0),
		}, "report", "summary")).To(Succeed())
		Expect(unstructured.SetNestedField(u.Object, "ghcr.io/foo/bar", "report", "artifact", "repository")).To(Succeed())
		Expect(unstructured.SetNestedField(u.Object, "v1.0.0", "report", "artifact", "tag")).To(Succeed())
		Expect(unstructured.SetNestedField(u.Object, map[string]any{
			"name": "Trivy", "vendor": "Aqua Security", "version": "0.70.0",
		}, "report", "scanner")).To(Succeed())
		Expect(unstructured.SetNestedField(u.Object, map[string]any{}, "report", "os")).To(Succeed())
		Expect(unstructured.SetNestedField(u.Object, "2026-09-11T00:00:00Z", "report", "updateTimestamp")).To(Succeed())
		Expect(unstructured.SetNestedSlice(u.Object, []any{}, "report", "vulnerabilities")).To(Succeed())
		return u
	}

	reconcile := func(name string) {
		r := &Reconciler{Client: k8sClient, Scheme: scheme.Scheme}
		_, err := r.Reconcile(ctx, ctrl.Request{Namespace: namespace, Name: name})
		Expect(err).NotTo(HaveOccurred())
	}

	It("creates no Finding when the namespace has no SignalPolicy", func() {
		report := newVulnReport("api-report", 3)
		Expect(k8sClient.Create(ctx, report)).To(Succeed())

		reconcile("api-report")

		findings := &candorv1alpha1.FindingList{}
		Expect(k8sClient.List(ctx, findings, client.InNamespace(namespace))).To(Succeed())
		Expect(findings.Items).To(BeEmpty())
	})

	It("creates a Finding when a SignalPolicy opts in and the signal clears the threshold", func() {
		policy := &candorv1alpha1.SignalPolicy{
			Name: testPolicyName, Namespace: namespace,
			Spec: candorv1alpha1.SignalPolicySpec{Providers: []string{ProviderName}, MinSeverity: signal.SeverityHigh},
		}
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())

		report := newVulnReport("api-report", 3)
		Expect(k8sClient.Create(ctx, report)).To(Succeed())

		reconcile("api-report")

		findings := &candorv1alpha1.FindingList{}
		Expect(k8sClient.List(ctx, findings, client.InNamespace(namespace))).To(Succeed())
		Expect(findings.Items).To(HaveLen(1))
		Expect(findings.Items[0].Spec.Severity).To(Equal(signal.SeverityCritical))
		Expect(findings.Items[0].Spec.Source.Provider).To(Equal(ProviderName))
		Expect(findings.Items[0].Spec.Source.Kind).To(Equal("Deployment"))
		Expect(findings.Items[0].Spec.Source.Name).To(Equal("api"))

		By("owning the Finding so it's garbage-collected with the VulnerabilityReport")
		Expect(findings.Items[0].OwnerReferences).To(HaveLen(1))
		Expect(findings.Items[0].OwnerReferences[0].Name).To(Equal("api-report"))
	})

	It("produces no Finding for a report with zero vulnerabilities", func() {
		policy := &candorv1alpha1.SignalPolicy{
			Name: testPolicyName, Namespace: namespace,
			Spec: candorv1alpha1.SignalPolicySpec{Providers: []string{ProviderName}, MinSeverity: signal.SeverityLow},
		}
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())

		report := newVulnReport("clean-report", 0)
		Expect(k8sClient.Create(ctx, report)).To(Succeed())

		reconcile("clean-report")

		findings := &candorv1alpha1.FindingList{}
		Expect(k8sClient.List(ctx, findings, client.InNamespace(namespace))).To(Succeed())
		Expect(findings.Items).To(BeEmpty())
	})

	It("resolves an existing Finding once the vulnerabilities that produced it are fixed", func() {
		policy := &candorv1alpha1.SignalPolicy{
			Name: testPolicyName, Namespace: namespace,
			Spec: candorv1alpha1.SignalPolicySpec{Providers: []string{ProviderName}, MinSeverity: signal.SeverityHigh},
		}
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())

		report := newVulnReport("api-report", 3)
		Expect(k8sClient.Create(ctx, report)).To(Succeed())
		reconcile("api-report")

		findings := &candorv1alpha1.FindingList{}
		Expect(k8sClient.List(ctx, findings, client.InNamespace(namespace))).To(Succeed())
		Expect(findings.Items).To(HaveLen(1))
		Expect(findings.Items[0].Status.VerificationOutcome).To(Equal(signal.VerificationStillPresent))

		By("fixing the vulnerabilities and re-reconciling")
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "api-report"}, report)).To(Succeed())
		Expect(unstructured.SetNestedField(report.Object, int64(0), "report", "summary", "criticalCount")).To(Succeed())
		Expect(k8sClient.Update(ctx, report)).To(Succeed())
		reconcile("api-report")

		Expect(k8sClient.List(ctx, findings, client.InNamespace(namespace))).To(Succeed())
		Expect(findings.Items).To(HaveLen(1), "the Finding must be kept, as the record that this happened - not deleted")
		Expect(findings.Items[0].Status.VerificationOutcome).To(Equal(signal.VerificationResolved))

		By("the vulnerabilities coming back")
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: "api-report"}, report)).To(Succeed())
		Expect(unstructured.SetNestedField(report.Object, int64(2), "report", "summary", "criticalCount")).To(Succeed())
		Expect(k8sClient.Update(ctx, report)).To(Succeed())
		reconcile("api-report")

		Expect(k8sClient.List(ctx, findings, client.InNamespace(namespace))).To(Succeed())
		Expect(findings.Items).To(HaveLen(1))
		Expect(findings.Items[0].Status.VerificationOutcome).To(Equal(signal.VerificationRecurred))
	})
})

var _ = Describe("provider.CRDInstalled", func() {
	It("reports true for VulnerabilityReport, which this suite registers", func() {
		installed, err := provider.CRDInstalled(k8sClient.RESTMapper(), GroupVersionKind)
		Expect(err).NotTo(HaveOccurred())
		Expect(installed).To(BeTrue())
	})

	It("reports false, not an error, for a CRD that doesn't exist in the cluster", func() {
		notInstalled := schema.GroupVersionKind{Group: "falco.example.org", Version: "v1alpha1", Kind: "FalcoEvent"}
		installed, err := provider.CRDInstalled(k8sClient.RESTMapper(), notInstalled)
		Expect(err).NotTo(HaveOccurred())
		Expect(installed).To(BeFalse())
	})
})
