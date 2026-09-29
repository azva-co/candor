package signal

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
)

func TestFindPolicy(t *testing.T) {
	c, _ := newFakeClient(t,
		policy("other-provider", []string{otherProvider}, SeverityLow),
		policy("trivy-policy", []string{testProvider}, SeverityHigh),
	)

	got, err := FindPolicy(context.Background(), c, testNamespace, testProvider)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Name != "trivy-policy" {
		t.Errorf("FindPolicy() = %v, want the trivy-policy object", got)
	}
}

func TestFindPolicy_NoneMatch(t *testing.T) {
	c, _ := newFakeClient(t, policy("policy", []string{otherProvider}, SeverityLow))

	got, err := FindPolicy(context.Background(), c, testNamespace, testProvider)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("FindPolicy() = %v, want nil (no policy enables %q)", got, testProvider)
	}
}

func withBudget(p *candorv1alpha1.SignalPolicy, maxCalls int32) *candorv1alpha1.SignalPolicy {
	p.Spec.Budget = &candorv1alpha1.Budget{MaxCalls: maxCalls, WindowSeconds: 86400}
	return p
}

func TestCheckBudget_NoBudgetConfigured_Unlimited(t *testing.T) {
	c, _ := newFakeClient(t)
	p := policy("policy", []string{testProvider}, SeverityLow) // no Budget

	for i := range 5 {
		allowed, err := CheckBudget(context.Background(), c, p)
		if err != nil {
			t.Fatal(err)
		}
		if !allowed {
			t.Fatalf("call %d: expected unlimited (no Budget configured) to always allow", i)
		}
	}
}

func TestCheckBudget_EnforcesLimit(t *testing.T) {
	p := withBudget(policy("policy", []string{testProvider}, SeverityLow), 3)
	c, _ := newFakeClient(t, p)

	ctx := context.Background()
	for i := range 3 {
		allowed, err := CheckBudget(ctx, c, p)
		if err != nil {
			t.Fatal(err)
		}
		if !allowed {
			t.Fatalf("call %d: expected allowed (under the limit of 3)", i)
		}
	}

	allowed, err := CheckBudget(ctx, c, p)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("4th call: expected denied (limit is 3)")
	}

	cond := findCondition(p.Status.Conditions, "BudgetExhausted")
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Errorf("BudgetExhausted condition = %v, want True", cond)
	}
}

func TestCheckBudget_WindowResets(t *testing.T) {
	p := withBudget(policy("policy", []string{testProvider}, SeverityLow), 1)
	c, _ := newFakeClient(t, p)
	ctx := context.Background()

	if allowed, err := CheckBudget(ctx, c, p); err != nil || !allowed {
		t.Fatalf("first call: allowed=%v err=%v, want true, nil", allowed, err)
	}
	if allowed, err := CheckBudget(ctx, c, p); err != nil || allowed {
		t.Fatalf("second call: allowed=%v err=%v, want false, nil (limit is 1)", allowed, err)
	}

	// Simulate the window having expired by backdating WindowStart past WindowSeconds.
	past := metav1.NewTime(time.Now().Add(-25 * time.Hour))
	p.Status.BudgetWindowStart = &past

	allowed, err := CheckBudget(ctx, c, p)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("after window reset: expected allowed again")
	}
	if p.Status.BudgetCallsUsed != 1 {
		t.Errorf("BudgetCallsUsed after reset = %d, want 1 (counter restarted)", p.Status.BudgetCallsUsed)
	}
}

func findCondition(conditions []metav1.Condition, t string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == t {
			return &conditions[i]
		}
	}
	return nil
}
