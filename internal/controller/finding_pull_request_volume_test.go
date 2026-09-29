package controller

import (
	"context"
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
	"github.com/azva-co/candor/internal/llm"
)

// This file is #41: the volume test docs/design.md:189 requires before a brake counts as proven,
// not just asserted. Each of the three brakes gets its own regression here, all through the real
// FindingReconciler.Reconcile path (not by calling internal/signal's check functions directly -
// those already have their own unit tests) - mirroring
// TestFindingReconciler_BudgetCostRegression's own justification: proving the limit holds against
// real volume, not that the accounting is internally consistent.
//
// The global rate limit's volume regression
// (TestFindingReconciler_ProposePullRequest_GlobalBudgetBlocksEvenWithNamespaceRoomToSpare) already
// lives in finding_pull_request_test.go, written alongside #39 - not duplicated here.

// vulnReportWithFixNamed is vulnReportWithFix (finding_pull_request_test.go) parameterised by
// name, for the volume tests below where every Finding needs its own distinct source object.
func vulnReportWithFixNamed(name string) *unstructured.Unstructured {
	u := vulnReportWithFix()
	u.SetName(name)
	return u
}

// TestFindingReconciler_ProposePullRequestCostRegression is the per-namespace cap's volume proof:
// N genuinely distinct Findings (each with its own fixable VulnerabilityReport, not a shared one)
// against a small per-namespace ceiling must produce exactly the ceiling's worth of pull requests -
// the rest degrade to Notify, not error, and are left retriable (see
// tryProposePullRequest's doc comment on why budget exhaustion never marks a fingerprint attempted).
func TestFindingReconciler_ProposePullRequestCostRegression(t *testing.T) {
	scheme := pullRequestScheme(t)

	policy := gitOpsPolicy(2) // ceiling of 2
	globalPolicy := permissiveOperatingPolicy()

	const n = 5
	objs := make([]client.Object, 0, 3+2*n)
	objs = append(objs, policy, gitHubTokenSecret(), globalPolicy)
	findings := make([]*candorv1alpha1.Finding, n)
	for i := range n {
		refName := fmt.Sprintf("vr-%d", i)
		f := findingRecommending(refName, candorv1alpha1.ActionProposePullRequest)
		f.Name = fmt.Sprintf("f%d", i)
		f.Status.Fingerprint = fmt.Sprintf("fp-%d", i)      // each genuinely distinct
		f.Status.EnrichedFingerprint = f.Status.Fingerprint // already past enrichment
		findings[i] = f
		objs = append(objs, f, vulnReportWithFixNamed(refName))
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).
		WithStatusSubresource(&candorv1alpha1.Finding{}, &candorv1alpha1.SignalPolicy{}, &candorv1alpha1.OperatingPolicy{}).Build()

	opener := &fakeOpener{url: testPRURL}
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: &countingLLM{resp: llm.Response{}}, GitOps: opener, Recorder: record.NewFakeRecorder(n)}

	ctx := context.Background()
	for _, f := range findings {
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: namespacedName(f)}); err != nil {
			t.Fatal(err)
		}
	}

	if got := opener.calls.Load(); got != 2 {
		t.Fatalf("Opener calls across %d distinct Findings with a per-namespace budget of 2 = %d, want exactly 2", n, got)
	}
}

// TestFindingReconciler_ProposePullRequest_PanicSwitchMidRun_StopsSubsequentAttempts is the panic
// switch's volume proof: flipping to Audit mid-run, matching how an operator would actually reach
// for it, must stop every attempt after that point - not just be effective for a Finding that was
// already in Audit mode from the start (that's TestFindingReconciler_ProposePullRequest_AuditMode_IsAGenuineFullStop).
func TestFindingReconciler_ProposePullRequest_PanicSwitchMidRun_StopsSubsequentAttempts(t *testing.T) {
	scheme := pullRequestScheme(t)

	policy := gitOpsPolicy(100) // plenty of per-namespace room - the panic switch is what's tested
	globalPolicy := permissiveOperatingPolicy()
	globalPolicy.Spec.Mode = candorv1alpha1.OperatingModeActive

	const n = 4
	objs := make([]client.Object, 0, 3+2*n)
	objs = append(objs, policy, gitHubTokenSecret(), globalPolicy)
	findings := make([]*candorv1alpha1.Finding, n)
	for i := range n {
		refName := fmt.Sprintf("vr-%d", i)
		f := findingRecommending(refName, candorv1alpha1.ActionProposePullRequest)
		f.Name = fmt.Sprintf("f%d", i)
		f.Status.Fingerprint = fmt.Sprintf("fp-%d", i)
		f.Status.EnrichedFingerprint = f.Status.Fingerprint
		findings[i] = f
		objs = append(objs, f, vulnReportWithFixNamed(refName))
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).
		WithStatusSubresource(&candorv1alpha1.Finding{}, &candorv1alpha1.SignalPolicy{}, &candorv1alpha1.OperatingPolicy{}).Build()

	opener := &fakeOpener{url: testPRURL}
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: &countingLLM{resp: llm.Response{}}, GitOps: opener, Recorder: record.NewFakeRecorder(n)}
	ctx := context.Background()

	// First half: Active mode, pull requests open normally.
	half := n / 2
	for _, f := range findings[:half] {
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: namespacedName(f)}); err != nil {
			t.Fatal(err)
		}
	}
	if got := opener.calls.Load(); got != int32(half) {
		t.Fatalf("Opener calls after the first %d Findings (Active mode) = %d, want %d", half, got, half)
	}

	// An operator reaches for the panic switch mid-run - exactly the scenario docs/design.md:189
	// describes, not a cluster that started in Audit.
	gotGlobal := &candorv1alpha1.OperatingPolicy{}
	if err := c.Get(ctx, client.ObjectKey{Name: testOperatingPolicyName}, gotGlobal); err != nil {
		t.Fatal(err)
	}
	gotGlobal.Spec.Mode = candorv1alpha1.OperatingModeAudit
	if err := c.Update(ctx, gotGlobal); err != nil {
		t.Fatal(err)
	}

	// Second half: Audit mode - no further attempts, regardless of how much per-namespace or
	// global budget remains.
	for _, f := range findings[half:] {
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: namespacedName(f)}); err != nil {
			t.Fatal(err)
		}
	}
	if got := opener.calls.Load(); got != int32(half) {
		t.Fatalf("Opener calls after flipping to Audit mid-run = %d, want still %d (no further attempts)", got, half)
	}
}
