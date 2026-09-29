package controller

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
	"github.com/azva-co/candor/internal/llm"
)

// testProvider is shared across this package's test files (finding_controller_test.go,
// signalpolicy_controller_test.go too) purely to avoid repeating the literal - it isn't
// internal/provider/trivy.ProviderName, importing that here would be a real (if harmless) coupling
// these tests don't need.
const testProvider = "trivy"

// testFingerprint1 and testFingerprint2 are two distinct fingerprint values shared across this
// package's test files - a real value never needs to be anything but "some string that changed",
// so there's no reason each file should invent its own.
const (
	testFingerprint1 = "fp-1"
	testFingerprint2 = "fp-2"
)

// testPolicyName is shared across this package's test files - every SignalPolicy they build is
// named "policy", and there's no reason each file should repeat the literal.
const testPolicyName = "policy"

// Shared across this package's test files - every test Finding here watches the same fictional
// Deployment via the same fictional VulnerabilityReport, and every fake enrichment response uses
// the same example hypothesis, so there's no reason each file should repeat these literals.
const (
	testKind               = "Deployment"
	testResourceName       = "api"
	testRefKindVulnReport  = "VulnerabilityReport"
	testCauseOutdatedImage = "outdated base image"
)

// countingLLM is a fake llm.Client that counts calls and returns a fixed response - enough to
// prove the gate around it, without needing a real API key or network access in CI.
type countingLLM struct {
	calls atomic.Int32
	resp  llm.Response
	err   error
}

func (f *countingLLM) Enrich(ctx context.Context, req llm.Request) (llm.Response, error) {
	f.calls.Add(1)
	return f.resp, f.err
}

func newTestFinding(name string) *candorv1alpha1.Finding {
	return &candorv1alpha1.Finding{
		Name: name, Namespace: corev1.NamespaceDefault,
		Spec: candorv1alpha1.FindingSpec{
			Source: candorv1alpha1.FindingSource{
				Provider: testProvider, Kind: testKind, Name: testResourceName,
				RefKind: testRefKindVulnReport, RefName: "api-report",
			},
			Severity: "CRITICAL",
			Summary:  "3 critical vulns",
		},
		// Set by internal/signal.Ingest in production; set directly here since these tests
		// exercise FindingReconciler in isolation from Ingest.
		Status: candorv1alpha1.FindingStatus{Fingerprint: testFingerprint1},
	}
}

func TestFindingReconciler_NoLLMConfigured_NoOp(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	finding := newTestFinding("f1")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(finding).WithStatusSubresource(&candorv1alpha1.Finding{}).Build()

	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: nil}
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: namespacedName(finding)})
	if err != nil {
		t.Fatal(err)
	}
	// No assertion beyond "didn't error" - there's no LLM to have been called, which is the point.
}

func TestFindingReconciler_NeedsEnrichment_CallsLLMOnce(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	finding := newTestFinding("f1")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(finding).WithStatusSubresource(&candorv1alpha1.Finding{}).Build()

	fakeLLM := &countingLLM{resp: llm.Response{Hypotheses: []llm.Hypothesis{
		{Cause: testCauseOutdatedImage, Confidence: 0.82, Rationale: "known CVE fixed upstream"},
	}}}
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: fakeLLM}

	ctx := context.Background()
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: namespacedName(finding)}); err != nil {
		t.Fatal(err)
	}

	if got := fakeLLM.calls.Load(); got != 1 {
		t.Fatalf("LLM calls = %d, want 1", got)
	}

	got := &candorv1alpha1.Finding{}
	if err := c.Get(ctx, namespacedName(finding), got); err != nil {
		t.Fatal(err)
	}
	if got.Status.EnrichedFingerprint != testFingerprint1 {
		t.Errorf("EnrichedFingerprint = %q, want %q", got.Status.EnrichedFingerprint, testFingerprint1)
	}
	if len(got.Status.Hypotheses) != 1 {
		t.Fatalf("got %d hypotheses, want 1", len(got.Status.Hypotheses))
	}
	h := got.Status.Hypotheses[0]
	if h.Cause != testCauseOutdatedImage || h.Confidence != 82 || h.Rationale == "" {
		t.Errorf("hypothesis = %+v, unexpected content (want Confidence=82, the 0.82 float converted to a percentage)", h)
	}
}

// TestFindingReconciler_CostRegression is the design doc's own required check, now with a real
// (fake, but interface-real) LLM call to count: N reconciles over unchanged content must produce
// exactly one LLM call. If this regresses, Candor has the exact k8sgpt failure mode it exists to
// avoid - 9,300 calls for 164 stable findings.
func TestFindingReconciler_CostRegression(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	finding := newTestFinding("f1")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(finding).WithStatusSubresource(&candorv1alpha1.Finding{}).Build()

	fakeLLM := &countingLLM{resp: llm.Response{Hypotheses: []llm.Hypothesis{{Cause: "x", Confidence: 0.5}}}}
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: fakeLLM}
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: namespacedName(finding)}

	const n = 10
	for i := range n {
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}

	if got := fakeLLM.calls.Load(); got != 1 {
		t.Fatalf("LLM calls across %d reconciles of unchanged content = %d, want exactly 1", n, got)
	}

	// Now the content actually changes (a new signal ingest would update Spec + Status.Fingerprint
	// - simulated directly here since Ingest itself is tested in internal/signal).
	got := &candorv1alpha1.Finding{}
	if err := c.Get(ctx, req.NamespacedName, got); err != nil {
		t.Fatal(err)
	}
	got.Status.Fingerprint = testFingerprint2
	if err := c.Status().Update(ctx, got); err != nil {
		t.Fatal(err)
	}

	for i := range n {
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("post-change iteration %d: %v", i, err)
		}
	}

	if got := fakeLLM.calls.Load(); got != 2 {
		t.Fatalf("LLM calls after content changed and %d more reconciles = %d, want exactly 2 (one for each distinct fingerprint, ever)", n, got)
	}
}

func namespacedName(f *candorv1alpha1.Finding) types.NamespacedName {
	return types.NamespacedName{Namespace: f.Namespace, Name: f.Name}
}

func testPolicy(maxCalls int32) *candorv1alpha1.SignalPolicy {
	return &candorv1alpha1.SignalPolicy{
		Name: testPolicyName, Namespace: corev1.NamespaceDefault,
		Spec: candorv1alpha1.SignalPolicySpec{
			Providers: []string{testProvider},
			Budget:    &candorv1alpha1.Budget{MaxCalls: maxCalls, WindowSeconds: 86400},
		},
	}
}

func TestFindingReconciler_BudgetExhausted_SkipsLLMAndEmitsEvent(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	finding := newTestFinding("f1")
	policy := testPolicy(0) // already exhausted - zero calls allowed
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(finding, policy).
		WithStatusSubresource(&candorv1alpha1.Finding{}, &candorv1alpha1.SignalPolicy{}).Build()

	fakeLLM := &countingLLM{resp: llm.Response{Hypotheses: []llm.Hypothesis{{Cause: "x", Confidence: 0.5}}}}
	recorder := record.NewFakeRecorder(10)
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: fakeLLM, Recorder: recorder}

	ctx := context.Background()
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: namespacedName(finding)}); err != nil {
		t.Fatal(err)
	}

	if got := fakeLLM.calls.Load(); got != 0 {
		t.Fatalf("LLM calls = %d, want 0 (budget already exhausted)", got)
	}

	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "BudgetExhausted") {
			t.Errorf("event = %q, want it to mention BudgetExhausted", event)
		}
	default:
		t.Fatal("expected a BudgetExhausted event, got none")
	}
}

func TestFindingReconciler_WithinBudget_CallsLLMAndDecrementsBudget(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	finding := newTestFinding("f1")
	policy := testPolicy(5)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(finding, policy).
		WithStatusSubresource(&candorv1alpha1.Finding{}, &candorv1alpha1.SignalPolicy{}).Build()

	fakeLLM := &countingLLM{resp: llm.Response{Hypotheses: []llm.Hypothesis{{Cause: "x", Confidence: 0.5}}}}
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: fakeLLM, Recorder: record.NewFakeRecorder(10)}

	ctx := context.Background()
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: namespacedName(finding)}); err != nil {
		t.Fatal(err)
	}
	if got := fakeLLM.calls.Load(); got != 1 {
		t.Fatalf("LLM calls = %d, want 1", got)
	}

	got := &candorv1alpha1.SignalPolicy{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: corev1.NamespaceDefault, Name: testPolicyName}, got); err != nil {
		t.Fatal(err)
	}
	if got.Status.BudgetCallsUsed != 1 {
		t.Errorf("BudgetCallsUsed = %d, want 1", got.Status.BudgetCallsUsed)
	}
}

// TestFindingReconciler_BudgetCostRegression proves the budget ceiling actually caps real LLM
// calls, not just that CheckBudget's own bookkeeping is correct in isolation (budget_test.go
// already covers that): N reconciles against a policy with a budget of 2 must produce exactly 2
// LLM calls and (N-2) BudgetExhausted skips, even though every one of the N reconciles is a
// distinct Finding that genuinely needs enrichment (unlike the fingerprint cost regression test,
// this is about volume exceeding a cap, not unchanged content).
func TestFindingReconciler_BudgetCostRegression(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(2)
	const n = 5
	objs := make([]client.Object, 0, 1+n)
	objs = append(objs, policy)
	findings := make([]*candorv1alpha1.Finding, n)
	for i := range n {
		f := newTestFinding(fmt.Sprintf("f%d", i))
		f.Status.Fingerprint = fmt.Sprintf("fp-%d", i) // each one distinct - genuinely needs enrichment
		findings[i] = f
		objs = append(objs, f)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).
		WithStatusSubresource(&candorv1alpha1.Finding{}, &candorv1alpha1.SignalPolicy{}).Build()

	fakeLLM := &countingLLM{resp: llm.Response{Hypotheses: []llm.Hypothesis{{Cause: "x", Confidence: 0.5}}}}
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: fakeLLM, Recorder: record.NewFakeRecorder(n)}

	ctx := context.Background()
	for _, f := range findings {
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: namespacedName(f)}); err != nil {
			t.Fatal(err)
		}
	}

	if got := fakeLLM.calls.Load(); got != 2 {
		t.Fatalf("LLM calls across %d distinct Findings with a budget of 2 = %d, want exactly 2", n, got)
	}
}
