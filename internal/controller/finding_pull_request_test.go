package controller

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
	"github.com/azva-co/candor/internal/gitops"
	"github.com/azva-co/candor/internal/llm"
	"github.com/azva-co/candor/internal/provider/trivy"
)

const (
	testSecretName          = "github-token"
	testPRURL               = "https://github.com/acme/gitops/pull/1"
	testOperatingPolicyName = "default"
)

// fakeOpener is a fake gitops.Opener that records whether it was called - enough to prove the
// reconciler's decision of whether to open a pull request at all, without making a real GitHub
// call (internal/gitops/github_test.go already covers what GitHubOpener itself sends).
type fakeOpener struct {
	calls atomic.Int32
	url   string
	err   error
}

func (f *fakeOpener) Open(ctx context.Context, token string, repo *candorv1alpha1.GitOpsRepo, fix gitops.Fix, finding *candorv1alpha1.Finding) (string, error) {
	f.calls.Add(1)
	return f.url, f.err
}

func pullRequestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	scheme.AddKnownTypeWithName(trivy.GroupVersionKind, &unstructured.Unstructured{})
	listGVK := trivy.GroupVersionKind
	listGVK.Kind += "List"
	scheme.AddKnownTypeWithName(listGVK, &unstructured.UnstructuredList{})
	return scheme
}

// vulnReportWithFix builds a VulnerabilityReport unstructured object whose vulnerabilities all
// agree on fixedVersion - internal/gitops.ComputeFix needs this to produce a Fix at all.
func vulnReportWithFix() *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(trivy.GroupVersionKind)
	u.SetName("vr-1")
	u.SetNamespace(corev1.NamespaceDefault)
	_ = unstructured.SetNestedField(u.Object, "ghcr.io/foo/bar", "report", "artifact", "repository")
	_ = unstructured.SetNestedField(u.Object, "v1.0.0", "report", "artifact", "tag")
	_ = unstructured.SetNestedSlice(u.Object, []any{
		map[string]any{"fixedVersion": "v1.2.0"},
	}, "report", "vulnerabilities")
	return u
}

func gitOpsPolicy(maxPullRequests int32) *candorv1alpha1.SignalPolicy {
	return &candorv1alpha1.SignalPolicy{
		Name: testPolicyName, Namespace: corev1.NamespaceDefault,
		Spec: candorv1alpha1.SignalPolicySpec{
			Providers: []string{testProvider},
			GitOpsRepo: &candorv1alpha1.GitOpsRepo{
				Owner: "acme", Repo: "gitops", Path: "values.yaml", YAMLPath: "image.tag",
				SecretRef: corev1.LocalObjectReference{Name: testSecretName},
			},
			PullRequestBudget: &candorv1alpha1.PullRequestBudget{MaxPullRequests: maxPullRequests, WindowSeconds: 86400},
		},
	}
}

// permissiveOperatingPolicy has plenty of global headroom - used by every test where the global
// brake isn't what's under test, so CheckGlobalPullRequestBudget's fail-closed default (no
// OperatingPolicy) doesn't mask what the test actually wants to prove.
func permissiveOperatingPolicy() *candorv1alpha1.OperatingPolicy {
	return &candorv1alpha1.OperatingPolicy{
		Name: testOperatingPolicyName,
		Spec: candorv1alpha1.OperatingPolicySpec{
			PullRequestRateLimit: &candorv1alpha1.PullRequestRateLimit{MaxPullRequests: 100, WindowSeconds: 86400},
		},
	}
}

func gitHubTokenSecret() *corev1.Secret {
	return &corev1.Secret{
		Name: testSecretName, Namespace: corev1.NamespaceDefault,
		Data: map[string][]byte{"token": []byte("test-token")},
	}
}

// findingRecommending builds a Finding already past enrichment (EnrichedFingerprint matches
// Fingerprint, so Reconcile's enrichment gate is a no-op and only tryProposePullRequest's own
// logic is under test) with recommendedAction already set on its top hypothesis.
func findingRecommending(refName, action string) *candorv1alpha1.Finding {
	return &candorv1alpha1.Finding{
		Name: "f1", Namespace: corev1.NamespaceDefault,
		Spec: candorv1alpha1.FindingSpec{
			Source: candorv1alpha1.FindingSource{
				Provider: testProvider, Kind: testKind, Name: testResourceName,
				RefKind: testRefKindVulnReport, RefName: refName,
			},
			Severity: "CRITICAL",
			Summary:  "3 critical vulns",
		},
		Status: candorv1alpha1.FindingStatus{
			Fingerprint:         testFingerprint1,
			EnrichedFingerprint: testFingerprint1,
			Hypotheses: []candorv1alpha1.Hypothesis{
				{Cause: testCauseOutdatedImage, Confidence: 80, Rationale: "fix available", RecommendedAction: action},
			},
		},
	}
}

func TestFindingReconciler_ProposePullRequest_OpensPR(t *testing.T) {
	scheme := pullRequestScheme(t)
	finding := findingRecommending("vr-1", candorv1alpha1.ActionProposePullRequest)
	policy := gitOpsPolicy(1)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(finding, policy, gitHubTokenSecret(), vulnReportWithFix(), permissiveOperatingPolicy()).
		WithStatusSubresource(&candorv1alpha1.Finding{}, &candorv1alpha1.SignalPolicy{}, &candorv1alpha1.OperatingPolicy{}).Build()

	opener := &fakeOpener{url: testPRURL}
	recorder := record.NewFakeRecorder(10)
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: &countingLLM{resp: llm.Response{}}, GitOps: opener, Recorder: recorder}

	ctx := context.Background()
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: namespacedName(finding)}); err != nil {
		t.Fatal(err)
	}

	if got := opener.calls.Load(); got != 1 {
		t.Fatalf("Opener calls = %d, want 1", got)
	}

	got := &candorv1alpha1.Finding{}
	if err := c.Get(ctx, namespacedName(finding), got); err != nil {
		t.Fatal(err)
	}
	if got.Status.ProposedPullRequestURL != opener.url {
		t.Errorf("ProposedPullRequestURL = %q, want %q", got.Status.ProposedPullRequestURL, opener.url)
	}

	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "PullRequestProposed") {
			t.Errorf("event = %q, want it to mention PullRequestProposed", event)
		}
	default:
		t.Fatal("expected a PullRequestProposed event, got none")
	}
}

func TestFindingReconciler_ProposePullRequest_NotRecommended_OpenerNeverCalled(t *testing.T) {
	scheme := pullRequestScheme(t)
	// A fix is mechanically computable (vulnReportWithFix exists), but the top hypothesis
	// recommends Notify - the reconciler must never override that with its own judgement.
	finding := findingRecommending("vr-1", candorv1alpha1.ActionNotify)
	policy := gitOpsPolicy(1)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(finding, policy, gitHubTokenSecret(), vulnReportWithFix()).
		WithStatusSubresource(&candorv1alpha1.Finding{}, &candorv1alpha1.SignalPolicy{}).Build()

	opener := &fakeOpener{url: testPRURL}
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: &countingLLM{resp: llm.Response{}}, GitOps: opener, Recorder: record.NewFakeRecorder(10)}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: namespacedName(finding)}); err != nil {
		t.Fatal(err)
	}
	if got := opener.calls.Load(); got != 0 {
		t.Fatalf("Opener calls = %d, want 0 (top hypothesis recommended Notify)", got)
	}
}

func TestFindingReconciler_ProposePullRequest_NoMechanicalFix_OpenerNeverCalled(t *testing.T) {
	scheme := pullRequestScheme(t)
	// RecommendedAction says ProposePullRequest, but the referenced VulnerabilityReport doesn't
	// exist at all - ComputeFix must independently refuse regardless of the model's opinion.
	finding := findingRecommending("does-not-exist", candorv1alpha1.ActionProposePullRequest)
	policy := gitOpsPolicy(1)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(finding, policy, gitHubTokenSecret()).
		WithStatusSubresource(&candorv1alpha1.Finding{}, &candorv1alpha1.SignalPolicy{}).Build()

	opener := &fakeOpener{url: testPRURL}
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: &countingLLM{resp: llm.Response{}}, GitOps: opener, Recorder: record.NewFakeRecorder(10)}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: namespacedName(finding)}); err != nil {
		t.Fatal(err)
	}
	if got := opener.calls.Load(); got != 0 {
		t.Fatalf("Opener calls = %d, want 0 (no mechanical fix computable)", got)
	}

	got := &candorv1alpha1.Finding{}
	if err := c.Get(context.Background(), namespacedName(finding), got); err != nil {
		t.Fatal(err)
	}
	if got.Status.ProposedPullRequestURL != "" {
		t.Errorf("ProposedPullRequestURL = %q, want empty", got.Status.ProposedPullRequestURL)
	}
}

func TestFindingReconciler_ProposePullRequest_BudgetExhausted_SkipsAndEmitsEvent(t *testing.T) {
	scheme := pullRequestScheme(t)
	finding := findingRecommending("vr-1", candorv1alpha1.ActionProposePullRequest)
	policy := gitOpsPolicy(0) // already exhausted
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(finding, policy, gitHubTokenSecret(), vulnReportWithFix()).
		WithStatusSubresource(&candorv1alpha1.Finding{}, &candorv1alpha1.SignalPolicy{}).Build()

	opener := &fakeOpener{url: testPRURL}
	recorder := record.NewFakeRecorder(10)
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: &countingLLM{resp: llm.Response{}}, GitOps: opener, Recorder: recorder}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: namespacedName(finding)}); err != nil {
		t.Fatal(err)
	}
	if got := opener.calls.Load(); got != 0 {
		t.Fatalf("Opener calls = %d, want 0 (pull request budget exhausted)", got)
	}

	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "PullRequestBudgetExhausted") {
			t.Errorf("event = %q, want it to mention PullRequestBudgetExhausted", event)
		}
	default:
		t.Fatal("expected a PullRequestBudgetExhausted event, got none")
	}
}

// TestFindingReconciler_ProposePullRequest_NoMechanicalFix_DoesNotRetryOnResync proves the
// ProposedPullRequestFingerprint gate actually holds across repeated reconciles of unchanged
// content (a periodic resync, not just a single call) - the same volume-regression shape
// docs/design.md requires for a brake, applied to the "no fix exists" verdict rather than a
// numeric ceiling: N reconciles must compute the fix exactly once, not once per reconcile.
func TestFindingReconciler_ProposePullRequest_NoMechanicalFix_DoesNotRetryOnResync(t *testing.T) {
	scheme := pullRequestScheme(t)
	finding := findingRecommending("does-not-exist", candorv1alpha1.ActionProposePullRequest)
	policy := gitOpsPolicy(1)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(finding, policy, gitHubTokenSecret()).
		WithStatusSubresource(&candorv1alpha1.Finding{}, &candorv1alpha1.SignalPolicy{}).Build()

	opener := &fakeOpener{url: testPRURL}
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: &countingLLM{resp: llm.Response{}}, GitOps: opener, Recorder: record.NewFakeRecorder(10)}

	ctx := context.Background()
	req := ctrl.Request{NamespacedName: namespacedName(finding)}
	const n = 5
	for i := range n {
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}
	if got := opener.calls.Load(); got != 0 {
		t.Fatalf("Opener calls = %d, want 0 across %d reconciles of the same unfixable content", got, n)
	}
}

// TestFindingReconciler_ProposePullRequest_ErrorOpeningRetriesOnNextReconcile proves the opposite
// of the fingerprint gate above: a real error opening the pull request must NOT be treated as
// "decided" for this fingerprint, or a transient GitHub outage would permanently give up on an
// otherwise-fixable Finding.
func TestFindingReconciler_ProposePullRequest_ErrorOpeningRetriesOnNextReconcile(t *testing.T) {
	scheme := pullRequestScheme(t)
	finding := findingRecommending("vr-1", candorv1alpha1.ActionProposePullRequest)
	policy := gitOpsPolicy(2)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(finding, policy, gitHubTokenSecret(), vulnReportWithFix(), permissiveOperatingPolicy()).
		WithStatusSubresource(&candorv1alpha1.Finding{}, &candorv1alpha1.SignalPolicy{}, &candorv1alpha1.OperatingPolicy{}).Build()

	opener := &fakeOpener{err: fmt.Errorf("simulated GitHub API outage")}
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: &countingLLM{resp: llm.Response{}}, GitOps: opener, Recorder: record.NewFakeRecorder(10)}

	ctx := context.Background()
	req := ctrl.Request{NamespacedName: namespacedName(finding)}

	if _, err := r.Reconcile(ctx, req); err == nil {
		t.Fatal("expected the opener's error to surface from Reconcile")
	}
	if got := opener.calls.Load(); got != 1 {
		t.Fatalf("Opener calls after first (failing) reconcile = %d, want 1", got)
	}

	opener.err = nil
	opener.url = "https://github.com/acme/gitops/pull/2"
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("retry reconcile: %v", err)
	}
	if got := opener.calls.Load(); got != 2 {
		t.Fatalf("Opener calls after the outage cleared = %d, want 2 (the fingerprint must still be retriable)", got)
	}
}

func TestFindingReconciler_ProposePullRequest_NoOpenerWired_NoOp(t *testing.T) {
	scheme := pullRequestScheme(t)
	finding := findingRecommending("vr-1", candorv1alpha1.ActionProposePullRequest)
	policy := gitOpsPolicy(1)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(finding, policy, gitHubTokenSecret(), vulnReportWithFix()).
		WithStatusSubresource(&candorv1alpha1.Finding{}, &candorv1alpha1.SignalPolicy{}).Build()

	// GitOps deliberately left nil - matches a deployment where the capability isn't wired up.
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: &countingLLM{resp: llm.Response{}}, Recorder: record.NewFakeRecorder(10)}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: namespacedName(finding)}); err != nil {
		t.Fatal(err)
	}
}

// TestFindingReconciler_ProposePullRequest_AuditMode_IsAGenuineFullStop is the regression #40
// exists for: docs/design.md:189's panic switch must stop ProposePullRequest before either budget
// is even checked, not just before the pull request opens - otherwise flipping to Audit still
// quietly spends a namespace's (and the cluster's) allowance on attempts that never happen.
func TestFindingReconciler_ProposePullRequest_AuditMode_IsAGenuineFullStop(t *testing.T) {
	scheme := pullRequestScheme(t)
	finding := findingRecommending("vr-1", candorv1alpha1.ActionProposePullRequest)
	policy := gitOpsPolicy(5)
	auditPolicy := permissiveOperatingPolicy()
	auditPolicy.Spec.Mode = candorv1alpha1.OperatingModeAudit

	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(finding, policy, gitHubTokenSecret(), vulnReportWithFix(), auditPolicy).
		WithStatusSubresource(&candorv1alpha1.Finding{}, &candorv1alpha1.SignalPolicy{}, &candorv1alpha1.OperatingPolicy{}).Build()

	opener := &fakeOpener{url: testPRURL}
	recorder := record.NewFakeRecorder(10)
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: &countingLLM{resp: llm.Response{}}, GitOps: opener, Recorder: recorder}

	ctx := context.Background()
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: namespacedName(finding)}); err != nil {
		t.Fatal(err)
	}
	if got := opener.calls.Load(); got != 0 {
		t.Fatalf("Opener calls = %d, want 0 - Audit mode must block before opening anything", got)
	}

	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "AuditModeActive") {
			t.Errorf("event = %q, want it to mention AuditModeActive", event)
		}
	default:
		t.Fatal("expected an AuditModeActive event, got none")
	}

	gotPolicy := &candorv1alpha1.SignalPolicy{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: corev1.NamespaceDefault, Name: testPolicyName}, gotPolicy); err != nil {
		t.Fatal(err)
	}
	if gotPolicy.Status.PullRequestsOpened != 0 {
		t.Errorf("namespace's PullRequestsOpened = %d, want 0 - Audit mode must not spend the per-namespace budget", gotPolicy.Status.PullRequestsOpened)
	}

	gotGlobal := &candorv1alpha1.OperatingPolicy{}
	if err := c.Get(ctx, client.ObjectKey{Name: testOperatingPolicyName}, gotGlobal); err != nil {
		t.Fatal(err)
	}
	if gotGlobal.Status.PullRequestsOpened != 0 {
		t.Errorf("global PullRequestsOpened = %d, want 0 - Audit mode must not spend the global budget either", gotGlobal.Status.PullRequestsOpened)
	}
}

// TestFindingReconciler_ProposePullRequest_ActiveMode_ProceedsNormally proves Mode=Active (the
// default) doesn't itself block anything - only Audit does.
func TestFindingReconciler_ProposePullRequest_ActiveMode_ProceedsNormally(t *testing.T) {
	scheme := pullRequestScheme(t)
	finding := findingRecommending("vr-1", candorv1alpha1.ActionProposePullRequest)
	policy := gitOpsPolicy(1)
	activePolicy := permissiveOperatingPolicy()
	activePolicy.Spec.Mode = candorv1alpha1.OperatingModeActive

	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(finding, policy, gitHubTokenSecret(), vulnReportWithFix(), activePolicy).
		WithStatusSubresource(&candorv1alpha1.Finding{}, &candorv1alpha1.SignalPolicy{}, &candorv1alpha1.OperatingPolicy{}).Build()

	opener := &fakeOpener{url: testPRURL}
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: &countingLLM{resp: llm.Response{}}, GitOps: opener, Recorder: record.NewFakeRecorder(10)}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: namespacedName(finding)}); err != nil {
		t.Fatal(err)
	}
	if got := opener.calls.Load(); got != 1 {
		t.Fatalf("Opener calls = %d, want 1 (Mode=Active must not block anything)", got)
	}
}

// TestFindingReconciler_ProposePullRequest_NoOperatingPolicyAtAll_DeniesGlobally proves
// internal/signal.CheckGlobalPullRequestBudget's fail-closed default holds end-to-end through the
// reconciler: everything else about this Finding would succeed, but with no OperatingPolicy
// object anywhere in the cluster, ProposePullRequest stays off.
func TestFindingReconciler_ProposePullRequest_NoOperatingPolicyAtAll_DeniesGlobally(t *testing.T) {
	scheme := pullRequestScheme(t)
	finding := findingRecommending("vr-1", candorv1alpha1.ActionProposePullRequest)
	policy := gitOpsPolicy(1)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(finding, policy, gitHubTokenSecret(), vulnReportWithFix()).
		WithStatusSubresource(&candorv1alpha1.Finding{}, &candorv1alpha1.SignalPolicy{}).Build()

	opener := &fakeOpener{url: testPRURL}
	recorder := record.NewFakeRecorder(10)
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: &countingLLM{resp: llm.Response{}}, GitOps: opener, Recorder: recorder}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: namespacedName(finding)}); err != nil {
		t.Fatal(err)
	}
	if got := opener.calls.Load(); got != 0 {
		t.Fatalf("Opener calls = %d, want 0 - ProposePullRequest must stay off cluster-wide until an OperatingPolicy exists", got)
	}

	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "GlobalPullRequestBudgetExhausted") {
			t.Errorf("event = %q, want it to mention GlobalPullRequestBudgetExhausted", event)
		}
	default:
		t.Fatal("expected a GlobalPullRequestBudgetExhausted event, got none")
	}
}

// TestFindingReconciler_ProposePullRequest_GlobalBudgetBlocksEvenWithNamespaceRoomToSpare is the
// regression #39 exists for: docs/design.md:189 requires "a global rate limit across all
// namespaces, so one noisy provider cannot exhaust the whole cluster's allowance." Two different
// namespaces, each with plenty of per-namespace budget, collectively exceed a small global
// ceiling - the second must be blocked by the global check even though its own namespace has
// room to spare.
func TestFindingReconciler_ProposePullRequest_GlobalBudgetBlocksEvenWithNamespaceRoomToSpare(t *testing.T) {
	scheme := pullRequestScheme(t)

	finding1 := findingRecommending("vr-1", candorv1alpha1.ActionProposePullRequest)
	policy1 := gitOpsPolicy(100) // plenty of per-namespace room

	const secondNamespace = "team-b"
	finding2 := findingRecommending("vr-2", candorv1alpha1.ActionProposePullRequest)
	finding2.Namespace = secondNamespace
	finding2.Name = "f2"
	policy2 := gitOpsPolicy(100)
	policy2.Namespace = secondNamespace
	secret2 := gitHubTokenSecret()
	secret2.Namespace = secondNamespace
	report2 := vulnReportWithFix()
	report2.SetName("vr-2")
	report2.SetNamespace(secondNamespace)

	// The whole point of this test: only one pull request fits in the global window, despite
	// both namespaces individually allowing up to 100.
	globalPolicy := permissiveOperatingPolicy()
	globalPolicy.Spec.PullRequestRateLimit.MaxPullRequests = 1

	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(finding1, policy1, gitHubTokenSecret(), vulnReportWithFix(),
			finding2, policy2, secret2, report2, globalPolicy).
		WithStatusSubresource(&candorv1alpha1.Finding{}, &candorv1alpha1.SignalPolicy{}, &candorv1alpha1.OperatingPolicy{}).Build()

	opener := &fakeOpener{url: testPRURL}
	recorder := record.NewFakeRecorder(10)
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: &countingLLM{resp: llm.Response{}}, GitOps: opener, Recorder: recorder}

	ctx := context.Background()
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: namespacedName(finding1)}); err != nil {
		t.Fatal(err)
	}
	if got := opener.calls.Load(); got != 1 {
		t.Fatalf("after the first namespace's Finding: Opener calls = %d, want 1", got)
	}
	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "PullRequestProposed") {
			t.Fatalf("first reconcile event = %q, want it to mention PullRequestProposed", event)
		}
	default:
		t.Fatal("expected a PullRequestProposed event after the first reconcile, got none")
	}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: namespacedName(finding2)}); err != nil {
		t.Fatal(err)
	}
	if got := opener.calls.Load(); got != 1 {
		t.Fatalf("after the second namespace's Finding: Opener calls = %d, want still 1 (global ceiling of 1 already spent by the first namespace)", got)
	}

	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "GlobalPullRequestBudgetExhausted") {
			t.Errorf("event = %q, want it to mention GlobalPullRequestBudgetExhausted", event)
		}
	default:
		t.Fatal("expected a GlobalPullRequestBudgetExhausted event, got none")
	}

	// The second namespace's own budget shows the attempt was counted locally too, even though
	// the pull request never actually opened - its own budget was never the constraint.
	gotPolicy2 := &candorv1alpha1.SignalPolicy{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: secondNamespace, Name: testPolicyName}, gotPolicy2); err != nil {
		t.Fatal(err)
	}
	if gotPolicy2.Status.PullRequestsOpened != 1 {
		t.Errorf("second namespace's PullRequestsOpened = %d, want 1", gotPolicy2.Status.PullRequestsOpened)
	}
}

// TestFindingReconciler_ProposePullRequest_MissingSecret_NeverConsumesBudget is the regression for
// a misconfigured (here, entirely missing) GitOpsRepo Secret: this fails identically on every
// retry, so it must never touch either budget - checking the Secret before either one is exactly
// what stops a typo'd Secret from silently exhausting a namespace's (or the cluster's) entire pull
// request allowance, as low as 1/24h by default, without a single pull request ever opening.
func TestFindingReconciler_ProposePullRequest_MissingSecret_NeverConsumesBudget(t *testing.T) {
	scheme := pullRequestScheme(t)
	finding := findingRecommending("vr-1", candorv1alpha1.ActionProposePullRequest)
	policy := gitOpsPolicy(1)
	globalPolicy := permissiveOperatingPolicy()

	// gitHubTokenSecret() deliberately omitted - the misconfiguration under test.
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(finding, policy, vulnReportWithFix(), globalPolicy).
		WithStatusSubresource(&candorv1alpha1.Finding{}, &candorv1alpha1.SignalPolicy{}, &candorv1alpha1.OperatingPolicy{}).Build()

	opener := &fakeOpener{url: testPRURL}
	r := &FindingReconciler{Client: c, Scheme: scheme, LLM: &countingLLM{resp: llm.Response{}}, GitOps: opener, Recorder: record.NewFakeRecorder(10)}

	ctx := context.Background()
	req := ctrl.Request{NamespacedName: namespacedName(finding)}

	// Retried 3 times, matching what controller-runtime's own backoff would actually do against a
	// persistent error - the whole point is that this must not behave differently on retry N than
	// on retry 1.
	for i := range 3 {
		if _, err := r.Reconcile(ctx, req); err == nil {
			t.Fatalf("reconcile %d: expected an error (Secret missing), got nil", i)
		}
	}
	if got := opener.calls.Load(); got != 0 {
		t.Fatalf("Opener calls = %d, want 0 - a missing Secret must never reach GitOps.Open", got)
	}

	gotPolicy := &candorv1alpha1.SignalPolicy{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: corev1.NamespaceDefault, Name: testPolicyName}, gotPolicy); err != nil {
		t.Fatal(err)
	}
	if gotPolicy.Status.PullRequestsOpened != 0 {
		t.Errorf("namespace's PullRequestsOpened = %d, want 0 across 3 retries of a persistent Secret error", gotPolicy.Status.PullRequestsOpened)
	}

	gotGlobal := &candorv1alpha1.OperatingPolicy{}
	if err := c.Get(ctx, client.ObjectKey{Name: testOperatingPolicyName}, gotGlobal); err != nil {
		t.Fatal(err)
	}
	if gotGlobal.Status.PullRequestsOpened != 0 {
		t.Errorf("global PullRequestsOpened = %d, want 0 across 3 retries of a persistent Secret error", gotGlobal.Status.PullRequestsOpened)
	}
}
