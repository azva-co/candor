package signal

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
)

func withGitOpsRepo(p *candorv1alpha1.SignalPolicy) *candorv1alpha1.SignalPolicy {
	p.Spec.GitOpsRepo = &candorv1alpha1.GitOpsRepo{
		Owner: "acme", Repo: "gitops", Path: "values.yaml", YAMLPath: "image.tag",
		SecretRef: corev1.LocalObjectReference{Name: "github-token"},
	}
	return p
}

func withPullRequestBudget(p *candorv1alpha1.SignalPolicy, maxPullRequests int32) *candorv1alpha1.SignalPolicy {
	p.Spec.PullRequestBudget = &candorv1alpha1.PullRequestBudget{MaxPullRequests: maxPullRequests, WindowSeconds: 86400}
	return p
}

func TestCheckPullRequestBudget_NoGitOpsRepo_NeverAllowed(t *testing.T) {
	p := policy("policy", []string{testProvider}, SeverityLow) // no GitOpsRepo
	c, _ := newFakeClient(t, p)

	allowed, err := CheckPullRequestBudget(context.Background(), c, p)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Error("CheckPullRequestBudget() = true, want false (no GitOpsRepo configured - nothing to check a budget against)")
	}
}

// TestCheckPullRequestBudget_OmittedBudget_AppliesConservativeDefault proves docs/design.md:189's
// "does not ship without a cap" holds even when an operator sets GitOpsRepo but never configures
// PullRequestBudget - unlike Budget, omission here must never mean unlimited.
func TestCheckPullRequestBudget_OmittedBudget_AppliesConservativeDefault(t *testing.T) {
	p := withGitOpsRepo(policy("policy", []string{testProvider}, SeverityLow)) // no PullRequestBudget
	c, _ := newFakeClient(t, p)
	ctx := context.Background()

	for i := range DefaultMaxPullRequests {
		allowed, err := CheckPullRequestBudget(ctx, c, p)
		if err != nil {
			t.Fatal(err)
		}
		if !allowed {
			t.Fatalf("call %d: expected allowed (under the default limit of %d)", i, DefaultMaxPullRequests)
		}
	}

	if allowed, err := CheckPullRequestBudget(ctx, c, p); err != nil || allowed {
		t.Fatalf("call after default limit: allowed=%v err=%v, want false, nil", allowed, err)
	}
}

// TestCheckPullRequestBudget_EnforcesLimit is the volume-regression pattern this project's own
// design doc requires for a brake (TestFindingReconciler_BudgetCostRegression's shape): N
// genuinely distinct attempts against a small ceiling, asserting exactly the ceiling's worth
// succeed - not that the accounting is internally consistent.
func TestCheckPullRequestBudget_EnforcesLimit(t *testing.T) {
	p := withPullRequestBudget(withGitOpsRepo(policy("policy", []string{testProvider}, SeverityLow)), 3)
	c, _ := newFakeClient(t, p)
	ctx := context.Background()

	allowedCount := 0
	const attempts = 10
	for range attempts {
		allowed, err := CheckPullRequestBudget(ctx, c, p)
		if err != nil {
			t.Fatal(err)
		}
		if allowed {
			allowedCount++
		}
	}

	if allowedCount != 3 {
		t.Fatalf("allowed %d of %d attempts against a ceiling of 3, want exactly 3", allowedCount, attempts)
	}

	cond := findCondition(p.Status.Conditions, "PullRequestBudgetExhausted")
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Errorf("PullRequestBudgetExhausted condition = %v, want True", cond)
	}
}

func TestCheckPullRequestBudget_WindowResets(t *testing.T) {
	p := withPullRequestBudget(withGitOpsRepo(policy("policy", []string{testProvider}, SeverityLow)), 1)
	c, _ := newFakeClient(t, p)
	ctx := context.Background()

	if allowed, err := CheckPullRequestBudget(ctx, c, p); err != nil || !allowed {
		t.Fatalf("first call: allowed=%v err=%v, want true, nil", allowed, err)
	}
	if allowed, err := CheckPullRequestBudget(ctx, c, p); err != nil || allowed {
		t.Fatalf("second call: allowed=%v err=%v, want false, nil (limit is 1)", allowed, err)
	}

	past := metav1.NewTime(time.Now().Add(-25 * time.Hour))
	p.Status.PullRequestWindowStart = &past

	allowed, err := CheckPullRequestBudget(ctx, c, p)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("after window reset: expected allowed again")
	}
	if p.Status.PullRequestsOpened != 1 {
		t.Errorf("PullRequestsOpened after reset = %d, want 1 (counter restarted)", p.Status.PullRequestsOpened)
	}
}
