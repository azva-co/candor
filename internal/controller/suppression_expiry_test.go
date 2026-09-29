package controller

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
)

func newTestSuppression(name string, expiresAt *metav1.Time) *candorv1alpha1.Suppression {
	return &candorv1alpha1.Suppression{
		Name: name, Namespace: corev1.NamespaceDefault,
		Spec: candorv1alpha1.SuppressionSpec{
			Fingerprint: testFingerprint1,
			Reason:      "known false positive",
			ExpiresAt:   expiresAt,
		},
	}
}

func newSuppressionReconciler(t *testing.T, objs ...client.Object) (*SuppressionReconciler, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).
		WithStatusSubresource(&candorv1alpha1.Suppression{}).Build()
	return &SuppressionReconciler{Client: c, Scheme: scheme}, c
}

func TestSuppressionReconciler_NoExpiresAt_NoOp(t *testing.T) {
	s := newTestSuppression("s1", nil)
	r, c := newSuppressionReconciler(t, s)

	res, err := r.Reconcile(context.Background(), ctrl.Request{Namespace: s.Namespace, Name: s.Name})
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter != 0 {
		t.Errorf("RequeueAfter = %v, want 0 (no expiresAt to wait for)", res.RequeueAfter)
	}

	got := &candorv1alpha1.Suppression{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: s.Namespace, Name: s.Name}, got); err != nil {
		t.Fatal(err)
	}
	if len(got.Status.Conditions) != 0 {
		t.Errorf("Conditions = %v, want none (no expiresAt configured)", got.Status.Conditions)
	}
}

func TestSuppressionReconciler_NotYetExpired_SetsFalseAndRequeues(t *testing.T) {
	future := metav1.NewTime(time.Now().Add(1 * time.Hour))
	s := newTestSuppression("s1", &future)
	r, c := newSuppressionReconciler(t, s)

	res, err := r.Reconcile(context.Background(), ctrl.Request{Namespace: s.Namespace, Name: s.Name})
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter <= 0 {
		t.Errorf("RequeueAfter = %v, want a positive duration until expiry", res.RequeueAfter)
	}

	got := &candorv1alpha1.Suppression{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: s.Namespace, Name: s.Name}, got); err != nil {
		t.Fatal(err)
	}
	cond := findCondition(got.Status.Conditions, conditionExpired)
	if cond == nil || cond.Status != metav1.ConditionFalse {
		t.Errorf("Expired condition = %v, want False", cond)
	}
}

func TestSuppressionReconciler_Expired_SetsTrue(t *testing.T) {
	past := metav1.NewTime(time.Now().Add(-1 * time.Hour))
	s := newTestSuppression("s1", &past)
	r, c := newSuppressionReconciler(t, s)

	res, err := r.Reconcile(context.Background(), ctrl.Request{Namespace: s.Namespace, Name: s.Name})
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter != 0 {
		t.Errorf("RequeueAfter = %v, want 0 (already expired, nothing more to wait for)", res.RequeueAfter)
	}

	got := &candorv1alpha1.Suppression{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: s.Namespace, Name: s.Name}, got); err != nil {
		t.Fatal(err)
	}
	cond := findCondition(got.Status.Conditions, conditionExpired)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Errorf("Expired condition = %v, want True", cond)
	}
}

func findCondition(conditions []metav1.Condition, condType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == condType {
			return &conditions[i]
		}
	}
	return nil
}
