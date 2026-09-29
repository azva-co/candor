package signal

import (
	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
)

// InAuditMode reports whether ProposePullRequest is currently disabled cluster-wide by the panic
// switch (docs/design.md:189, OperatingPolicy.Spec.Mode). policy may be nil (no OperatingPolicy
// exists) - that is not audit mode by this function's own definition: with no rate limit object
// either, CheckGlobalPullRequestBudget already denies everything on its own (see that function's
// doc comment for why that's a fail-closed default, not a numeric one). Keeping the two checks
// independent - "is there a policy to allow this at all" vs. "has a human explicitly paused it" -
// means each brake's own test proves its own claim, rather than one mechanism's test accidentally
// depending on the other's default.
func InAuditMode(policy *candorv1alpha1.OperatingPolicy) bool {
	return policy != nil && policy.Spec.Mode == candorv1alpha1.OperatingModeAudit
}
