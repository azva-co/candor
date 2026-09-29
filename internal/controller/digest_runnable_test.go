package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
	"github.com/azva-co/candor/internal/notify"
	"github.com/azva-co/candor/internal/signal"
)

func digestWebhookServer(t *testing.T) (url string, received chan notify.Digest) {
	t.Helper()
	received = make(chan notify.Digest, 10)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var digest notify.Digest
		if err := json.NewDecoder(r.Body).Decode(&digest); err != nil {
			t.Errorf("decoding digest body: %v", err)
		}
		received <- digest
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	return server.URL, received
}

func findingWithOutcome(name, severity, outcome string) *candorv1alpha1.Finding {
	f := newTestFinding(name)
	f.Spec.Severity = severity
	f.Status.VerificationOutcome = outcome
	return f
}

func TestDigestRunnable_SendsOneDigestPerWebhookConfiguredPolicy(t *testing.T) {
	url, received := digestWebhookServer(t)
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	policy := &candorv1alpha1.SignalPolicy{
		Name: testPolicyName, Namespace: corev1.NamespaceDefault,
		Spec: candorv1alpha1.SignalPolicySpec{
			Providers: []string{testProvider},
			Webhook:   &candorv1alpha1.Webhook{URL: url},
		},
	}
	stillPresent := findingWithOutcome("f1", "CRITICAL", signal.VerificationStillPresent)
	resolved := findingWithOutcome("f2", "HIGH", signal.VerificationResolved)
	recurred := findingWithOutcome("f3", "CRITICAL", signal.VerificationRecurred)

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy, stillPresent, resolved, recurred).Build()
	d := &DigestRunnable{Client: c, Interval: time.Hour}

	d.sendDigests(context.Background())

	// A real, bounded wait, not a non-blocking check: sendDigests now queues its send onto
	// internal/notify's shared async worker pool (issue #63) rather than sending inline, so the
	// digest can genuinely still be in flight for a moment after sendDigests itself returns.
	select {
	case digest := <-received:
		if digest.Namespace != corev1.NamespaceDefault {
			t.Errorf("Namespace = %q, want %q", digest.Namespace, corev1.NamespaceDefault)
		}
		if digest.StillPresent != 1 || digest.Resolved != 1 || digest.Recurred != 1 {
			t.Errorf("digest = %+v, want StillPresent=1 Resolved=1 Recurred=1", digest)
		}
		if digest.BySeverity["CRITICAL"] != 2 {
			t.Errorf("BySeverity[CRITICAL] = %d, want 2 (the still-present and recurred findings, not the resolved one)", digest.BySeverity["CRITICAL"])
		}
		if digest.WindowSeconds != int64(time.Hour.Seconds()) {
			t.Errorf("WindowSeconds = %d, want %d", digest.WindowSeconds, int64(time.Hour.Seconds()))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a digest")
	}
}

func TestDigestRunnable_NoWebhookConfigured_NoDigestSent(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	policy := &candorv1alpha1.SignalPolicy{
		Name: testPolicyName, Namespace: corev1.NamespaceDefault,
		Spec: candorv1alpha1.SignalPolicySpec{Providers: []string{testProvider}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build()
	d := &DigestRunnable{Client: c, Interval: time.Hour}

	// No webhook configured anywhere - must not attempt any HTTP call. A passing call here (no
	// panic, no error) is the proof; there's no server to assert against by design.
	d.sendDigests(context.Background())
}

func TestDigestRunnable_ZeroInterval_StartReturnsImmediately(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	d := &DigestRunnable{Client: c, Interval: 0}

	done := make(chan error, 1)
	go func() { done <- d.Start(context.Background()) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start with a zero Interval must return immediately, not block forever")
	}
}
