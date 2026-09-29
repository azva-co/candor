package controller

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
	"github.com/azva-co/candor/internal/llm"
)

// newTestSuppressionFor always mutes testFingerprint1 - the one newTestFinding's Findings start
// with - since every test in this file is about that exact match. The one test that needs a
// non-matching fingerprint (TestFindingReconciler_NewFingerprintNotSuppressed_ResurfacesAutomatically)
// changes the Finding's fingerprint instead, which is the real-world equivalent anyway.
func newTestSuppressionFor(reason string, expiresAt *metav1.Time) *candorv1alpha1.Suppression {
	return &candorv1alpha1.Suppression{
		Name: "suppression", Namespace: corev1.NamespaceDefault,
		Spec: candorv1alpha1.SuppressionSpec{
			Fingerprint: testFingerprint1,
			Reason:      reason,
			ExpiresAt:   expiresAt,
		},
	}
}

func TestFindingReconciler_ActiveSuppression_SkipsLLMAndSetsCondition(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	f := newTestFinding("f1") // fingerprint testFingerprint1
	s := newTestSuppressionFor("known false positive, TICKET-123", nil)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(f, s).
		WithStatusSubresource(&candorv1alpha1.Finding{}).Build()

	fakeLLM := &countingLLM{resp: llm.Response{Hypotheses: []llm.Hypothesis{{Cause: "x", Confidence: 0.5}}}}
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: fakeLLM}

	ctx := context.Background()
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: namespacedName(f)}); err != nil {
		t.Fatal(err)
	}

	if got := fakeLLM.calls.Load(); got != 0 {
		t.Fatalf("LLM calls = %d, want 0 (fingerprint is actively suppressed)", got)
	}

	got := &candorv1alpha1.Finding{}
	if err := c.Get(ctx, namespacedName(f), got); err != nil {
		t.Fatal(err)
	}
	cond := findCondition(got.Status.Conditions, conditionSuppressed)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("Suppressed condition = %v, want True", cond)
	}
	if cond.Message != "known false positive, TICKET-123" {
		t.Errorf("Suppressed condition message = %q, want the Suppression's Reason", cond.Message)
	}
}

func TestFindingReconciler_ExpiredSuppression_DoesNotApply(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	f := newTestFinding("f1")
	past := metav1.NewTime(time.Now().Add(-1 * time.Hour))
	s := newTestSuppressionFor("expired reason", &past)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(f, s).
		WithStatusSubresource(&candorv1alpha1.Finding{}).Build()

	fakeLLM := &countingLLM{resp: llm.Response{Hypotheses: []llm.Hypothesis{{Cause: "x", Confidence: 0.5}}}}
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: fakeLLM}

	ctx := context.Background()
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: namespacedName(f)}); err != nil {
		t.Fatal(err)
	}

	if got := fakeLLM.calls.Load(); got != 1 {
		t.Fatalf("LLM calls = %d, want 1 (expired Suppression must not block enrichment)", got)
	}
}

func TestFindingReconciler_SuppressionLifted_ClearsConditionAndResumesEnrichment(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	f := newTestFinding("f1")
	s := newTestSuppressionFor("temporary mute", nil)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(f, s).
		WithStatusSubresource(&candorv1alpha1.Finding{}).Build()

	fakeLLM := &countingLLM{resp: llm.Response{Hypotheses: []llm.Hypothesis{{Cause: "x", Confidence: 0.5}}}}
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: fakeLLM}
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: namespacedName(f)}

	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if got := fakeLLM.calls.Load(); got != 0 {
		t.Fatalf("LLM calls while suppressed = %d, want 0", got)
	}

	// Lifting suppression (deleting the Suppression object) must let the Finding resurface: the
	// condition clears and enrichment resumes on the very next reconcile.
	if err := c.Delete(ctx, s); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}

	if got := fakeLLM.calls.Load(); got != 1 {
		t.Fatalf("LLM calls after Suppression lifted = %d, want 1", got)
	}

	got := &candorv1alpha1.Finding{}
	if err := c.Get(ctx, namespacedName(f), got); err != nil {
		t.Fatal(err)
	}
	if cond := findCondition(got.Status.Conditions, conditionSuppressed); cond != nil {
		t.Errorf("Suppressed condition = %v, want none (Suppression was lifted)", cond)
	}
}

func TestFindingReconciler_NewFingerprintNotSuppressed_ResurfacesAutomatically(t *testing.T) {
	// The core suppression-exactness claim (docs/design.md pillar 3): a Suppression mutes one
	// exact fingerprint. When the underlying content changes, Ingest writes a new fingerprint,
	// and this Finding is no longer suppressed by the old Suppression - no one has to remember to
	// delete or update it.
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	f := newTestFinding("f1")
	f.Status.Fingerprint = testFingerprint2 // content already changed from the suppressed fingerprint
	s := newTestSuppressionFor("mutes the old content only", nil)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(f, s).
		WithStatusSubresource(&candorv1alpha1.Finding{}).Build()

	fakeLLM := &countingLLM{resp: llm.Response{Hypotheses: []llm.Hypothesis{{Cause: "x", Confidence: 0.5}}}}
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: fakeLLM}

	ctx := context.Background()
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: namespacedName(f)}); err != nil {
		t.Fatal(err)
	}

	if got := fakeLLM.calls.Load(); got != 1 {
		t.Fatalf("LLM calls = %d, want 1 (new fingerprint isn't the one the Suppression mutes)", got)
	}
}
