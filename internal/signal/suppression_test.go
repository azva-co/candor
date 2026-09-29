package signal

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
)

func suppression(fingerprint string, expiresAt *metav1.Time) *candorv1alpha1.Suppression {
	return &candorv1alpha1.Suppression{
		Name: "s1", Namespace: testNamespace,
		Spec: candorv1alpha1.SuppressionSpec{
			Fingerprint: fingerprint,
			Reason:      "known false positive, tracked in TICKET-123",
			ExpiresAt:   expiresAt,
		},
	}
}

func TestFindActiveSuppression_NoMatch(t *testing.T) {
	c, _ := newFakeClient(t, suppression("fp-other", nil))

	got, err := FindActiveSuppression(context.Background(), c, testNamespace, "fp-1")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("FindActiveSuppression() = %v, want nil (no Suppression mutes fp-1)", got)
	}
}

func TestFindActiveSuppression_Matches(t *testing.T) {
	c, _ := newFakeClient(t, suppression("fp-1", nil))

	got, err := FindActiveSuppression(context.Background(), c, testNamespace, "fp-1")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Name != "s1" {
		t.Errorf("FindActiveSuppression() = %v, want the s1 object", got)
	}
}

func TestFindActiveSuppression_Expired_NoMatch(t *testing.T) {
	past := metav1.NewTime(time.Now().Add(-1 * time.Hour))
	c, _ := newFakeClient(t, suppression("fp-1", &past))

	got, err := FindActiveSuppression(context.Background(), c, testNamespace, "fp-1")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("FindActiveSuppression() = %v, want nil (expired Suppression must not match)", got)
	}
}

func TestFindActiveSuppression_NotYetExpired_Matches(t *testing.T) {
	future := metav1.NewTime(time.Now().Add(1 * time.Hour))
	c, _ := newFakeClient(t, suppression("fp-1", &future))

	got, err := FindActiveSuppression(context.Background(), c, testNamespace, "fp-1")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Name != "s1" {
		t.Errorf("FindActiveSuppression() = %v, want the s1 object (not yet expired)", got)
	}
}

func TestFindActiveSuppression_DifferentNamespace_NoMatch(t *testing.T) {
	s := suppression("fp-1", nil)
	s.Namespace = "other-namespace"
	c, _ := newFakeClient(t, s)

	got, err := FindActiveSuppression(context.Background(), c, testNamespace, "fp-1")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("FindActiveSuppression() = %v, want nil (Suppression is in a different namespace)", got)
	}
}
