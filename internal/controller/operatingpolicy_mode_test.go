package controller

import (
	"context"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
)

func operatingPolicyTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

// TestOperatingPolicyReconciler_ModeChange_EmitsEvent proves the panic switch is visible in
// Events, not just status - docs/design.md's brake definition requires both.
func TestOperatingPolicyReconciler_ModeChange_EmitsEvent(t *testing.T) {
	scheme := operatingPolicyTestScheme(t)
	policy := &candorv1alpha1.OperatingPolicy{
		Name: testOperatingPolicyName,
		Spec: candorv1alpha1.OperatingPolicySpec{Mode: candorv1alpha1.OperatingModeActive},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).
		WithStatusSubresource(&candorv1alpha1.OperatingPolicy{}).Build()
	recorder := record.NewFakeRecorder(10)
	r := &OperatingPolicyReconciler{Client: c, Scheme: scheme, Recorder: recorder}
	ctx := context.Background()
	req := ctrl.Request{Name: testOperatingPolicyName}

	// First reconcile: ObservedMode starts empty, so this establishes the baseline - no
	// transition, no event, matching NeedsEnrichment's own "nothing to compare against yet" case.
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-recorder.Events:
		t.Fatalf("unexpected event on the first reconcile (no prior observed mode to transition from): %q", event)
	default:
	}

	// Flip to Audit and reconcile again - now there's a real transition to report.
	got := &candorv1alpha1.OperatingPolicy{}
	if err := c.Get(ctx, req.NamespacedName, got); err != nil {
		t.Fatal(err)
	}
	got.Spec.Mode = candorv1alpha1.OperatingModeAudit
	if err := c.Update(ctx, got); err != nil {
		t.Fatal(err)
	}

	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "ModeChanged") || !strings.Contains(event, "Audit") {
			t.Errorf("event = %q, want it to mention ModeChanged and Audit", event)
		}
	default:
		t.Fatal("expected a ModeChanged event after flipping to Audit, got none")
	}

	final := &candorv1alpha1.OperatingPolicy{}
	if err := c.Get(ctx, req.NamespacedName, final); err != nil {
		t.Fatal(err)
	}
	if final.Status.ObservedMode != candorv1alpha1.OperatingModeAudit {
		t.Errorf("ObservedMode = %q, want %q", final.Status.ObservedMode, candorv1alpha1.OperatingModeAudit)
	}
}

// TestOperatingPolicyReconciler_NoModeChange_NoEvent proves reconciling unchanged content doesn't
// spam an event every time - the same "only report a real transition" rule
// internal/signal.Ingest's own notify path already follows for Finding events.
func TestOperatingPolicyReconciler_NoModeChange_NoEvent(t *testing.T) {
	scheme := operatingPolicyTestScheme(t)
	policy := &candorv1alpha1.OperatingPolicy{
		Name: testOperatingPolicyName,
		Spec: candorv1alpha1.OperatingPolicySpec{Mode: candorv1alpha1.OperatingModeActive},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).
		WithStatusSubresource(&candorv1alpha1.OperatingPolicy{}).Build()
	recorder := record.NewFakeRecorder(10)
	r := &OperatingPolicyReconciler{Client: c, Scheme: scheme, Recorder: recorder}
	ctx := context.Background()
	req := ctrl.Request{Name: testOperatingPolicyName}

	for i := range 3 {
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}

	select {
	case event := <-recorder.Events:
		t.Fatalf("unexpected event across %d reconciles with no mode change: %q", 3, event)
	default:
	}
}
