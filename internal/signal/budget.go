package signal

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
)

// defaultBudgetWindow matches SignalPolicySpec.Budget.WindowSeconds's +kubebuilder:default.
const defaultBudgetWindow = 24 * time.Hour

// Condition reasons shared by every rolling-window budget check in this package (CheckBudget,
// CheckPullRequestBudget, CheckGlobalPullRequestBudget) - one pair of constants instead of the
// same two literals repeated at each call site.
const (
	reasonWithinBudget = "WithinBudget"
	reasonLimitReached = "LimitReached"
)

// FindPolicy returns the first SignalPolicy in namespace that enables provider, or nil if none.
// This is the same lookup Ingest uses to decide whether to accept a signal at all - here it finds
// the policy whose Budget (if any) governs enrichment for signals it already accepted.
func FindPolicy(ctx context.Context, c client.Client, namespace, provider string) (*candorv1alpha1.SignalPolicy, error) {
	policies := &candorv1alpha1.SignalPolicyList{}
	if err := c.List(ctx, policies, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("listing SignalPolicies in namespace %s: %w", namespace, err)
	}
	for i := range policies.Items {
		if providerEnabled(policies.Items[i].Spec.Providers, provider) {
			return &policies.Items[i], nil
		}
	}
	return nil, nil
}

// CheckBudget reports whether policy has budget remaining for one more enrichment call. A nil
// Budget means unlimited - always true, no write. Otherwise this records the consumption (or the
// denial) via a single Status().Update(), resetting the window first if it has expired.
//
// Assumes FindingReconciler's default reconcile concurrency of 1 (controller-runtime's default
// for a single controller) - there is nothing else racing against this check-then-write, so no
// optimistic-concurrency retry is implemented. If that concurrency default ever changes for
// FindingReconciler specifically, this needs revisiting.
func CheckBudget(ctx context.Context, c client.Client, policy *candorv1alpha1.SignalPolicy) (bool, error) {
	b := policy.Spec.Budget
	if b == nil {
		return true, nil
	}

	window := time.Duration(b.WindowSeconds) * time.Second
	if window <= 0 {
		window = defaultBudgetWindow
	}

	now := metav1.Now()
	expired := policy.Status.BudgetWindowStart == nil || now.Sub(policy.Status.BudgetWindowStart.Time) >= window
	if expired {
		policy.Status.BudgetWindowStart = &now
		policy.Status.BudgetCallsUsed = 0
	}

	allowed := policy.Status.BudgetCallsUsed < b.MaxCalls

	condition := metav1.Condition{
		Type:               "BudgetExhausted",
		ObservedGeneration: policy.Generation,
	}
	if allowed {
		policy.Status.BudgetCallsUsed++
		condition.Status = metav1.ConditionFalse
		condition.Reason = reasonWithinBudget
		condition.Message = fmt.Sprintf("%d/%d calls used this window", policy.Status.BudgetCallsUsed, b.MaxCalls)
	} else {
		condition.Status = metav1.ConditionTrue
		condition.Reason = reasonLimitReached
		condition.Message = fmt.Sprintf("%d/%d calls used - enrichment degraded to deterministic-only until the window resets", policy.Status.BudgetCallsUsed, b.MaxCalls)
	}
	meta.SetStatusCondition(&policy.Status.Conditions, condition)

	if err := c.Status().Update(ctx, policy); err != nil {
		return false, fmt.Errorf("updating budget status on SignalPolicy %s/%s: %w", policy.Namespace, policy.Name, err)
	}

	return allowed, nil
}
