package controller

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
	"github.com/azva-co/candor/internal/llm"
	"github.com/azva-co/candor/internal/metrics"
)

// TestFindingReconciler_Metrics proves the self-observability metrics docs/design.md requires
// ("reconciles, LLM calls, tokens, spend vs budget, degraded state") actually move, not just that
// the wiring compiles - reading the real registered collectors via testutil, not a fake counter.
func TestFindingReconciler_Metrics(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(1)
	f1 := newTestFinding("f1")
	f2 := newTestFinding("f2")
	f2.Status.Fingerprint = testFingerprint2 // distinct, so it also needs enrichment
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(f1, f2, policy).
		WithStatusSubresource(&candorv1alpha1.Finding{}, &candorv1alpha1.SignalPolicy{}).Build()

	fakeLLM := &countingLLM{resp: llm.Response{Hypotheses: []llm.Hypothesis{{Cause: "x", Confidence: 0.5}}}}
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: fakeLLM, Recorder: record.NewFakeRecorder(10)}
	ctx := context.Background()

	before := testutil.ToFloat64(metrics.LLMCallsTotal.WithLabelValues("success"))

	// f1: within budget (1/1), calls the LLM.
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: namespacedName(f1)}); err != nil {
		t.Fatal(err)
	}
	// f2: budget now exhausted, skipped.
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: namespacedName(f2)}); err != nil {
		t.Fatal(err)
	}

	if got := testutil.ToFloat64(metrics.LLMCallsTotal.WithLabelValues("success")) - before; got != 1 {
		t.Errorf("candor_llm_calls_total{result=success} increased by %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.EnrichmentSkippedTotal.WithLabelValues("budget_exhausted")); got < 1 {
		t.Errorf("candor_enrichment_skipped_total{reason=budget_exhausted} = %v, want >= 1", got)
	}
	if got := testutil.ToFloat64(metrics.BudgetCallsUsed.WithLabelValues("default", "policy")); got != 1 {
		t.Errorf("candor_signalpolicy_budget_calls_used{namespace=default,signalpolicy=policy} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.BudgetCallsLimit.WithLabelValues("default", "policy")); got != 1 {
		t.Errorf("candor_signalpolicy_budget_calls_limit{namespace=default,signalpolicy=policy} = %v, want 1", got)
	}
}
