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

// DefaultMaxPullRequests is the ceiling applied when GitOpsRepo is configured but
// PullRequestBudget is omitted. Unlike Budget, omitting PullRequestBudget never means "unlimited"
// - docs/design.md:189 requires a cap on ProposePullRequest in the same change as the action
// itself, so there is no configuration that leaves it uncapped. One PR per window is a
// deliberately conservative starting point; an operator who wants more raises it explicitly.
const DefaultMaxPullRequests = 1

// MaxPullRequests resolves the effective per-window ceiling for policy: PullRequestBudget's own
// value if set, otherwise DefaultMaxPullRequests. CheckPullRequestBudget uses it to enforce the
// limit, and callers that just need to report it (e.g. an Event message) use it too, so the two
// can never silently disagree about what the ceiling actually is.
func MaxPullRequests(policy *candorv1alpha1.SignalPolicy) int32 {
	if b := policy.Spec.PullRequestBudget; b != nil {
		return b.MaxPullRequests
	}
	return DefaultMaxPullRequests
}

// CheckPullRequestBudget reports whether policy has budget remaining for one more
// ProposePullRequest action, and if so, records the consumption via a single Status().Update() -
// the same check-then-write shape as CheckBudget, and the same single-reconciler-concurrency
// assumption (see that function's doc comment). Returns false without error if policy has no
// GitOpsRepo configured at all - there is nothing to check a budget against.
func CheckPullRequestBudget(ctx context.Context, c client.Client, policy *candorv1alpha1.SignalPolicy) (bool, error) {
	if policy.Spec.GitOpsRepo == nil {
		return false, nil
	}

	maxPullRequests := MaxPullRequests(policy)
	windowSeconds := int32(0)
	if b := policy.Spec.PullRequestBudget; b != nil {
		windowSeconds = b.WindowSeconds
	}

	window := time.Duration(windowSeconds) * time.Second
	if window <= 0 {
		window = defaultBudgetWindow
	}

	now := metav1.Now()
	expired := policy.Status.PullRequestWindowStart == nil || now.Sub(policy.Status.PullRequestWindowStart.Time) >= window
	if expired {
		policy.Status.PullRequestWindowStart = &now
		policy.Status.PullRequestsOpened = 0
	}

	allowed := policy.Status.PullRequestsOpened < maxPullRequests

	condition := metav1.Condition{
		Type:               "PullRequestBudgetExhausted",
		ObservedGeneration: policy.Generation,
	}
	if allowed {
		policy.Status.PullRequestsOpened++
		condition.Status = metav1.ConditionFalse
		condition.Reason = reasonWithinBudget
		condition.Message = fmt.Sprintf("%d/%d pull requests opened this window", policy.Status.PullRequestsOpened, maxPullRequests)
	} else {
		condition.Status = metav1.ConditionTrue
		condition.Reason = reasonLimitReached
		condition.Message = fmt.Sprintf("%d/%d pull requests opened - ProposePullRequest degraded to Notify until the window resets", policy.Status.PullRequestsOpened, maxPullRequests)
	}
	meta.SetStatusCondition(&policy.Status.Conditions, condition)

	if err := c.Status().Update(ctx, policy); err != nil {
		return false, fmt.Errorf("updating pull request budget status on SignalPolicy %s/%s: %w", policy.Namespace, policy.Name, err)
	}

	return allowed, nil
}
