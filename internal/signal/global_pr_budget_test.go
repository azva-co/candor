package signal

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
)

func newOperatingPolicyClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).
		WithStatusSubresource(&candorv1alpha1.OperatingPolicy{}).Build()
}

func operatingPolicy(name string, maxPullRequests int32) *candorv1alpha1.OperatingPolicy {
	return &candorv1alpha1.OperatingPolicy{
		Name: name,
		Spec: candorv1alpha1.OperatingPolicySpec{
			PullRequestRateLimit: &candorv1alpha1.PullRequestRateLimit{MaxPullRequests: maxPullRequests, WindowSeconds: 86400},
		},
	}
}

func TestFindOperatingPolicy_None_ReturnsNil(t *testing.T) {
	c := newOperatingPolicyClient(t)
	got, err := FindOperatingPolicy(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("FindOperatingPolicy() = %v, want nil", got)
	}
}

func TestFindOperatingPolicy_PrefersConventionalName(t *testing.T) {
	c := newOperatingPolicyClient(t, operatingPolicy("aaa-first-alphabetically", 1), operatingPolicy(defaultOperatingPolicyName, 2))

	got, err := FindOperatingPolicy(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Name != defaultOperatingPolicyName {
		t.Errorf("FindOperatingPolicy() = %v, want the conventionally-named one even though it sorts second", got)
	}
}

func TestFindOperatingPolicy_MultipleNonConventional_PicksAlphabeticallyFirst(t *testing.T) {
	c := newOperatingPolicyClient(t, operatingPolicy("zzz", 1), operatingPolicy("aaa", 2))

	got, err := FindOperatingPolicy(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Name != "aaa" {
		t.Errorf("FindOperatingPolicy() = %v, want the deterministic (alphabetically first) fallback", got)
	}
}

// TestCheckGlobalPullRequestBudget_NoOperatingPolicy_DeniesRatherThanDefaulting proves the one
// place this brake deliberately differs from every other budget in this codebase: with no object
// to persist a count against, "allow anyway" would just be an uncounted, unpersisted brake - not a
// real one. Failing closed is the safe degradation here, not a numeric default.
func TestCheckGlobalPullRequestBudget_NoOperatingPolicy_DeniesRatherThanDefaulting(t *testing.T) {
	c := newOperatingPolicyClient(t)
	allowed, err := CheckGlobalPullRequestBudget(context.Background(), c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Error("CheckGlobalPullRequestBudget(nil) = true, want false - no object exists to persist a count against")
	}
}

func TestCheckGlobalPullRequestBudget_OmittedRateLimit_AppliesConservativeDefault(t *testing.T) {
	p := &candorv1alpha1.OperatingPolicy{Name: defaultOperatingPolicyName} // no PullRequestRateLimit
	c := newOperatingPolicyClient(t, p)
	ctx := context.Background()

	for i := range defaultGlobalMaxPullRequests {
		allowed, err := CheckGlobalPullRequestBudget(ctx, c, p)
		if err != nil {
			t.Fatal(err)
		}
		if !allowed {
			t.Fatalf("call %d: expected allowed (under the default limit of %d)", i, defaultGlobalMaxPullRequests)
		}
	}
	if allowed, err := CheckGlobalPullRequestBudget(ctx, c, p); err != nil || allowed {
		t.Fatalf("call after default limit: allowed=%v err=%v, want false, nil", allowed, err)
	}
}

// TestCheckGlobalPullRequestBudget_EnforcesLimit is the volume-regression shape docs/design.md
// requires for a brake: N genuinely distinct attempts against a small ceiling, asserting exactly
// the ceiling's worth succeed.
func TestCheckGlobalPullRequestBudget_EnforcesLimit(t *testing.T) {
	p := operatingPolicy(defaultOperatingPolicyName, 3)
	c := newOperatingPolicyClient(t, p)
	ctx := context.Background()

	allowedCount := 0
	const attempts = 10
	for range attempts {
		allowed, err := CheckGlobalPullRequestBudget(ctx, c, p)
		if err != nil {
			t.Fatal(err)
		}
		if allowed {
			allowedCount++
		}
	}
	if allowedCount != 3 {
		t.Fatalf("allowed %d of %d attempts against a global ceiling of 3, want exactly 3", allowedCount, attempts)
	}

	cond := findCondition(p.Status.Conditions, "GlobalPullRequestBudgetExhausted")
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Errorf("GlobalPullRequestBudgetExhausted condition = %v, want True", cond)
	}
}

func TestCheckGlobalPullRequestBudget_WindowResets(t *testing.T) {
	p := operatingPolicy(defaultOperatingPolicyName, 1)
	c := newOperatingPolicyClient(t, p)
	ctx := context.Background()

	if allowed, err := CheckGlobalPullRequestBudget(ctx, c, p); err != nil || !allowed {
		t.Fatalf("first call: allowed=%v err=%v, want true, nil", allowed, err)
	}
	if allowed, err := CheckGlobalPullRequestBudget(ctx, c, p); err != nil || allowed {
		t.Fatalf("second call: allowed=%v err=%v, want false, nil (limit is 1)", allowed, err)
	}

	past := metav1.NewTime(time.Now().Add(-25 * time.Hour))
	p.Status.PullRequestWindowStart = &past

	allowed, err := CheckGlobalPullRequestBudget(ctx, c, p)
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
