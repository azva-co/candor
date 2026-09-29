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

// defaultOperatingPolicyName is the conventional singleton name (see OperatingPolicy's doc
// comment and config/samples/candor_v1alpha1_operatingpolicy.yaml) - FindOperatingPolicy doesn't
// require this exact name, it just takes the first object found by name order, so the convention
// is what keeps "the first one" and "the one the operator meant" the same thing in practice.
const defaultOperatingPolicyName = "default"

// defaultGlobalMaxPullRequests is the ceiling applied when no OperatingPolicy exists at all, or
// one exists without a PullRequestRateLimit. Never unlimited, for the same reason
// PullRequestBudget never is - docs/design.md:189 requires this brake unconditionally. Set higher
// than PullRequestBudget's own per-namespace default (1) since this is the aggregate ceiling
// across every namespace in the cluster, not a single one.
const defaultGlobalMaxPullRequests = 5

// FindOperatingPolicy returns the cluster's OperatingPolicy, or nil if none exists - a fully
// supported configuration (see that type's doc comment), not an error. If more than one exists
// (OperatingPolicyReconciler flags this as a misconfiguration), the one named
// defaultOperatingPolicyName is preferred if present, otherwise the alphabetically first - either
// way, deterministic, not arbitrarily "whichever the list API returns first".
func FindOperatingPolicy(ctx context.Context, c client.Client) (*candorv1alpha1.OperatingPolicy, error) {
	policies := &candorv1alpha1.OperatingPolicyList{}
	if err := c.List(ctx, policies); err != nil {
		return nil, fmt.Errorf("listing OperatingPolicies: %w", err)
	}
	if len(policies.Items) == 0 {
		return nil, nil
	}

	best := &policies.Items[0]
	for i := range policies.Items {
		p := &policies.Items[i]
		if p.Name == defaultOperatingPolicyName {
			return p, nil
		}
		if p.Name < best.Name {
			best = p
		}
	}
	return best, nil
}

// CheckGlobalPullRequestBudget reports whether the cluster-wide pull request rate limit has room
// for one more ProposePullRequest action, and if so, records the consumption via a single
// Status().Update() on policy - the same check-then-write shape as CheckBudget and
// CheckPullRequestBudget, and the same single-reconciler-concurrency assumption (see CheckBudget's
// doc comment; this is checked from the same FindingReconciler).
//
// policy may be nil (no OperatingPolicy exists in the cluster at all). Unlike every other budget
// in this codebase, that denies rather than applying a numeric default: there's no object to
// persist a count against, so "allow anyway" would mean every FindingReconciler process invents
// its own uncounted, unpersisted window - not a real brake, just the appearance of one. Failing
// closed here is the same "degrade rather than fail" posture as everywhere else, applied to the
// one case where the safe degradation is zero rather than a lower number: ProposePullRequest stays
// globally disabled until an operator creates an OperatingPolicy (an empty one is enough to get
// defaultGlobalMaxPullRequests - see that constant's doc comment).
func CheckGlobalPullRequestBudget(ctx context.Context, c client.Client, policy *candorv1alpha1.OperatingPolicy) (bool, error) {
	if policy == nil {
		return false, nil
	}

	maxPullRequests := int32(defaultGlobalMaxPullRequests)
	windowSeconds := int32(0)
	if l := policy.Spec.PullRequestRateLimit; l != nil {
		maxPullRequests = l.MaxPullRequests
		windowSeconds = l.WindowSeconds
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
		Type:               "GlobalPullRequestBudgetExhausted",
		ObservedGeneration: policy.Generation,
	}
	if allowed {
		policy.Status.PullRequestsOpened++
		condition.Status = metav1.ConditionFalse
		condition.Reason = reasonWithinBudget
		condition.Message = fmt.Sprintf("%d/%d pull requests opened cluster-wide this window", policy.Status.PullRequestsOpened, maxPullRequests)
	} else {
		condition.Status = metav1.ConditionTrue
		condition.Reason = reasonLimitReached
		condition.Message = fmt.Sprintf("%d/%d pull requests opened cluster-wide - ProposePullRequest degraded to Notify everywhere until the window resets", policy.Status.PullRequestsOpened, maxPullRequests)
	}
	meta.SetStatusCondition(&policy.Status.Conditions, condition)

	if err := c.Status().Update(ctx, policy); err != nil {
		return false, fmt.Errorf("updating global pull request budget status on OperatingPolicy %s: %w", policy.Name, err)
	}

	return allowed, nil
}
