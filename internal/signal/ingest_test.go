package signal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
	"github.com/azva-co/candor/internal/metrics"
	"github.com/azva-co/candor/internal/notify"
)

const (
	// A local constant, not internal/provider/trivy's ProviderName - signal is provider-agnostic,
	// and importing trivy here would cycle back (trivy imports signal). Ingest doesn't care what
	// the provider is called; these tests just need a consistent, arbitrary value.
	testProvider  = "trivy"
	otherProvider = "falco" // any provider testProvider's policy doesn't enable
	testNamespace = "team-a"
	testKind      = "Deployment"
	testResource  = "api"
	testRefKind   = "VulnerabilityReport"
	testRefName   = "api-abc123"
)

func newFakeClient(t *testing.T, objs ...client.Object) (client.Client, *runtime.Scheme) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).
		WithStatusSubresource(&candorv1alpha1.Finding{}, &candorv1alpha1.SignalPolicy{}).Build()
	return c, scheme
}

// policy builds a SignalPolicy in testNamespace - every test in this file exercises the same
// namespace, so it isn't a parameter.
func policy(name string, providers []string, minSeverity string) *candorv1alpha1.SignalPolicy {
	return &candorv1alpha1.SignalPolicy{
		Name: name, Namespace: testNamespace,
		Spec: candorv1alpha1.SignalPolicySpec{Providers: providers, MinSeverity: minSeverity},
	}
}

// webhookServer records every Event it receives (decoded, for easy assertions) and returns a
// stop func alongside the received channel.
func webhookServer(t *testing.T) (url string, received chan notify.Event) {
	t.Helper()
	received = make(chan notify.Event, 10)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event notify.Event
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Errorf("decoding webhook body: %v", err)
		}
		received <- event
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	return server.URL, received
}

// waitForNotification blocks until an Event arrives on received or notifyWait elapses. Needed
// because notifyEvent (internal/signal/ingest.go) fires asynchronously in its own goroutine, not
// synchronously inside Ingest (issue #63) - a non-blocking check right after Ingest returns would
// race the goroutine rather than actually waiting for it.
func waitForNotification(t *testing.T, received chan notify.Event) notify.Event {
	t.Helper()
	select {
	case event := <-received:
		return event
	case <-time.After(notifyWait):
		t.Fatal("timed out waiting for a webhook notification")
		return notify.Event{}
	}
}

// assertNoNotification waits notifyWait for an Event that must never arrive. Like
// waitForNotification, this is a real wait, not a non-blocking check - the notification goroutine
// needs a chance to run at all before its absence means anything.
func assertNoNotification(t *testing.T, received chan notify.Event) {
	t.Helper()
	select {
	case event := <-received:
		t.Fatalf("expected no notification, got %+v", event)
	case <-time.After(notifyWait):
	}
}

// notifyWait bounds how long a test waits for (or, in assertNoNotification's case, waits out) the
// async notification goroutine, dispatched via internal/notify's own shared worker pool
// (SendAsync). Generous relative to how long a real send actually takes - webhookServer's own
// httptest.Server responds near-instantly - specifically to stay clear of scheduling delay under
// -race or a loaded CI runner, where a shorter value risked a spurious "timed out" failure on an
// otherwise-correct send that simply hadn't been scheduled yet.
const notifyWait = 2 * time.Second

func policyWithWebhook(providers []string, webhookURL string) *candorv1alpha1.SignalPolicy {
	p := policy("policy", providers, SeverityHigh)
	p.Spec.Webhook = &candorv1alpha1.Webhook{URL: webhookURL}
	return p
}

func testSignal(severity string) Signal {
	return Signal{
		Provider: testProvider, Severity: severity, Namespace: testNamespace,
		Kind: testKind, Name: testResource, RefKind: testRefKind, RefName: testRefName,
	}
}

func TestIngest_NoPolicy_Filtered(t *testing.T) {
	c, scheme := newFakeClient(t)

	result, err := Ingest(context.Background(), c, scheme, testSignal(SeverityCritical), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result != ResultFiltered {
		t.Errorf("result = %q, want %q (no SignalPolicy in namespace)", result, ResultFiltered)
	}
}

func TestIngest_BelowThreshold_Filtered(t *testing.T) {
	c, scheme := newFakeClient(t, policy("policy", []string{testProvider}, SeverityCritical))

	result, err := Ingest(context.Background(), c, scheme, testSignal(SeverityHigh), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result != ResultFiltered {
		t.Errorf("result = %q, want %q (HIGH below policy's CRITICAL threshold)", result, ResultFiltered)
	}
}

func TestIngest_WrongProvider_Filtered(t *testing.T) {
	c, scheme := newFakeClient(t, policy("policy", []string{otherProvider}, SeverityLow))

	result, err := Ingest(context.Background(), c, scheme, testSignal(SeverityCritical), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result != ResultFiltered {
		t.Errorf("result = %q, want %q (policy doesn't enable trivy)", result, ResultFiltered)
	}
}

func TestIngest_Creates(t *testing.T) {
	c, scheme := newFakeClient(t, policy("policy", []string{testProvider}, SeverityHigh))
	sig := testSignal(SeverityCritical)
	sig.Summary = "3 CRITICAL vulns"

	result, err := Ingest(context.Background(), c, scheme, sig, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result != ResultCreated {
		t.Fatalf("result = %q, want %q", result, ResultCreated)
	}

	findings := &candorv1alpha1.FindingList{}
	if err := c.List(context.Background(), findings); err != nil {
		t.Fatal(err)
	}
	if len(findings.Items) != 1 {
		t.Fatalf("got %d Findings, want 1", len(findings.Items))
	}
	f := findings.Items[0]
	if f.Spec.Severity != SeverityCritical || f.Spec.Summary != "3 CRITICAL vulns" || f.Spec.Source.Provider != testProvider {
		t.Errorf("Finding spec = %+v, unexpected content", f.Spec)
	}
}

func TestIngest_SameSignalTwice_UpdatesNotDuplicates(t *testing.T) {
	c, scheme := newFakeClient(t, policy("policy", []string{testProvider}, SeverityLow))
	sig := testSignal(SeverityHigh)
	sig.Summary = "first"

	if _, err := Ingest(context.Background(), c, scheme, sig, nil); err != nil {
		t.Fatal(err)
	}

	sig.Summary = "updated"
	result, err := Ingest(context.Background(), c, scheme, sig, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result != ResultUpdated {
		t.Errorf("result = %q, want %q", result, ResultUpdated)
	}

	findings := &candorv1alpha1.FindingList{}
	if err := c.List(context.Background(), findings); err != nil {
		t.Fatal(err)
	}
	if len(findings.Items) != 1 {
		t.Fatalf("got %d Findings for the same signal ingested twice, want 1 (re-ingest must update, not duplicate)", len(findings.Items))
	}
	if findings.Items[0].Spec.Summary != "updated" {
		t.Errorf("Summary = %q, want %q", findings.Items[0].Spec.Summary, "updated")
	}
}

func TestIngest_MultiplePolicies_AnyMatchAccepts(t *testing.T) {
	// A LOW-threshold policy for another provider must not block a HIGH-threshold trivy policy
	// from accepting a signal that clears it.
	c, scheme := newFakeClient(t,
		policy("policy1", []string{otherProvider}, SeverityLow),
		policy("policy2", []string{testProvider}, SeverityHigh),
	)

	result, err := Ingest(context.Background(), c, scheme, testSignal(SeverityCritical), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result != ResultCreated {
		t.Errorf("result = %q, want %q", result, ResultCreated)
	}
}

// TestIngest_RestrictToPolicy_IgnoresLaxerSiblingPolicy is the regression test for a real bug
// found via a live cluster (docs/design.md slice 10): the webhook receiver authenticates a
// request against one specific SignalPolicy's own secret, but without RestrictToPolicy, Ingest's
// namespace-wide "any policy accepts" semantics would let a laxer sibling policy accept (or route
// the notification for) a signal that was only ever authenticated against a different, stricter
// policy's credentials - defeating the point of per-policy authentication.
func TestIngest_RestrictToPolicy_IgnoresLaxerSiblingPolicy(t *testing.T) {
	strict := policy("strict", []string{testProvider}, SeverityCritical)
	c, scheme := newFakeClient(t,
		strict,
		policy("loose", []string{testProvider}, SeverityLow),
	)

	sig := testSignal(SeverityLow)
	sig.RestrictToPolicy = strict

	result, err := Ingest(context.Background(), c, scheme, sig, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result != ResultFiltered {
		t.Errorf("result = %q, want %q - a LOW signal restricted to the CRITICAL-only \"strict\" policy must not be accepted just because \"loose\" would take it", result, ResultFiltered)
	}

	findings := &candorv1alpha1.FindingList{}
	if err := c.List(context.Background(), findings); err != nil {
		t.Fatal(err)
	}
	if len(findings.Items) != 0 {
		t.Errorf("got %d findings, want 0", len(findings.Items))
	}
}

// The unrestricted sibling test above (TestIngest_MultiplePolicies_AnyMatchAccepts) proves the
// default namespace-wide behaviour is intentional and unchanged for providers with no per-object
// policy identity (Trivy) - this proves RestrictToPolicy actually narrows it when set.
func TestIngest_RestrictToPolicy_StillAcceptsWhenTheNamedPolicyItselfMatches(t *testing.T) {
	strict := policy("strict", []string{testProvider}, SeverityCritical)
	c, scheme := newFakeClient(t,
		strict,
		policy("loose", []string{testProvider}, SeverityLow),
	)

	sig := testSignal(SeverityCritical)
	sig.RestrictToPolicy = strict

	result, err := Ingest(context.Background(), c, scheme, sig, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result != ResultCreated {
		t.Errorf("result = %q, want %q", result, ResultCreated)
	}
}

// TestIngest_RestrictToPolicy_DoesNotResolveFindingSiblingPolicyStillWants is the regression test
// for a real bug found via a second /code-review high pass: findingName has no policy component,
// so a Finding is shared namespace-wide, not owned by whichever policy happened to create it. A
// signal authenticated against "strict" and failing "strict"'s own threshold must not resolve a
// Finding that "loose" - a real, still-active sibling policy - would still accept.
func TestIngest_RestrictToPolicy_DoesNotResolveFindingSiblingPolicyStillWants(t *testing.T) {
	loose := policy("loose", []string{testProvider}, SeverityLow)
	strict := policy("strict", []string{testProvider}, SeverityCritical)
	c, scheme := newFakeClient(t, loose, strict)

	// A LOW delivery (accepted by "loose") creates the Finding.
	lowSig := testSignal(SeverityLow)
	lowSig.RestrictToPolicy = loose
	if _, err := Ingest(context.Background(), c, scheme, lowSig, nil); err != nil {
		t.Fatal(err)
	}

	// The same underlying signal, now authenticated against "strict" instead - "strict" alone
	// wouldn't accept a LOW severity, but "loose" still would, so the Finding must survive.
	restrictedSig := testSignal(SeverityLow)
	restrictedSig.RestrictToPolicy = strict
	result, err := Ingest(context.Background(), c, scheme, restrictedSig, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result != ResultFiltered {
		t.Errorf("result = %q, want %q", result, ResultFiltered)
	}

	findings := &candorv1alpha1.FindingList{}
	if err := c.List(context.Background(), findings); err != nil {
		t.Fatal(err)
	}
	if len(findings.Items) != 1 {
		t.Fatalf("got %d findings, want 1 - the Finding must not have been deleted", len(findings.Items))
	}
	if findings.Items[0].Status.VerificationOutcome == VerificationResolved {
		t.Error("Finding was resolved - \"loose\" still accepts this content, so a request authenticated only against \"strict\" must not resolve it")
	}
}

func TestIngest_WritesFingerprint(t *testing.T) {
	c, scheme := newFakeClient(t, policy("policy", []string{testProvider}, SeverityLow))
	sig := testSignal(SeverityCritical)

	if _, err := Ingest(context.Background(), c, scheme, sig, nil); err != nil {
		t.Fatal(err)
	}

	findings := &candorv1alpha1.FindingList{}
	if err := c.List(context.Background(), findings); err != nil {
		t.Fatal(err)
	}
	got := findings.Items[0].Status.Fingerprint
	want := Fingerprint(sig)
	if got != want {
		t.Errorf("Status.Fingerprint = %q, want %q", got, want)
	}
	if got == "" {
		t.Error("Status.Fingerprint left empty")
	}
}

func TestIngest_Creates_SetsVerificationStillPresent(t *testing.T) {
	c, scheme := newFakeClient(t, policy("policy", []string{testProvider}, SeverityHigh))
	sig := testSignal(SeverityCritical)

	if _, err := Ingest(context.Background(), c, scheme, sig, nil); err != nil {
		t.Fatal(err)
	}

	findings := &candorv1alpha1.FindingList{}
	if err := c.List(context.Background(), findings); err != nil {
		t.Fatal(err)
	}
	if got := findings.Items[0].Status.VerificationOutcome; got != VerificationStillPresent {
		t.Errorf("VerificationOutcome = %q, want %q", got, VerificationStillPresent)
	}
}

func TestIngest_Filtered_NoExistingFinding_NoOp(t *testing.T) {
	c, scheme := newFakeClient(t, policy("policy", []string{testProvider}, SeverityCritical))

	result, err := Ingest(context.Background(), c, scheme, testSignal(SeverityLow), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result != ResultFiltered {
		t.Errorf("result = %q, want %q (nothing to resolve, never had a Finding)", result, ResultFiltered)
	}
}

// TestIngest_SeverityDropsBelowThreshold_Resolves proves the resolution path this slice adds: a
// Finding whose source later stops clearing any policy's threshold must be marked Resolved, not
// left showing its old, now-stale severity forever - this is the exact "no verification of its own
// remediation" gap docs/design.md pillar 4 exists to close.
func TestIngest_SeverityDropsBelowThreshold_Resolves(t *testing.T) {
	c, scheme := newFakeClient(t, policy("policy", []string{testProvider}, SeverityHigh))
	ctx := context.Background()

	if _, err := Ingest(ctx, c, scheme, testSignal(SeverityCritical), nil); err != nil {
		t.Fatal(err)
	}

	result, err := Ingest(ctx, c, scheme, testSignal(SeverityLow), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result != ResultResolved {
		t.Fatalf("result = %q, want %q", result, ResultResolved)
	}

	findings := &candorv1alpha1.FindingList{}
	if err := c.List(ctx, findings); err != nil {
		t.Fatal(err)
	}
	if len(findings.Items) != 1 {
		t.Fatalf("got %d Findings, want 1 (resolved, not deleted)", len(findings.Items))
	}
	if got := findings.Items[0].Status.VerificationOutcome; got != VerificationResolved {
		t.Errorf("VerificationOutcome = %q, want %q", got, VerificationResolved)
	}
}

func TestIngest_ResolvedThenRecurred(t *testing.T) {
	c, scheme := newFakeClient(t, policy("policy", []string{testProvider}, SeverityHigh))
	ctx := context.Background()

	if _, err := Ingest(ctx, c, scheme, testSignal(SeverityCritical), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Ingest(ctx, c, scheme, testSignal(SeverityLow), nil); err != nil {
		t.Fatal(err)
	}

	// Spec content is identical to the very first ingest (same severity, same summary) - only
	// Status.VerificationOutcome transitions, so CreateOrUpdate correctly reports Unchanged on the
	// Spec/ObjectMeta side. The Recurred transition is proven via Status below, not via Result.
	if _, err := Ingest(ctx, c, scheme, testSignal(SeverityCritical), nil); err != nil {
		t.Fatal(err)
	}

	findings := &candorv1alpha1.FindingList{}
	if err := c.List(ctx, findings); err != nil {
		t.Fatal(err)
	}
	if got := findings.Items[0].Status.VerificationOutcome; got != VerificationRecurred {
		t.Errorf("VerificationOutcome = %q, want %q (was Resolved, source produced a real signal again)", got, VerificationRecurred)
	}
}

func TestIngest_ResolvedAgain_NoOp(t *testing.T) {
	c, scheme := newFakeClient(t, policy("policy", []string{testProvider}, SeverityHigh))
	ctx := context.Background()

	if _, err := Ingest(ctx, c, scheme, testSignal(SeverityCritical), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Ingest(ctx, c, scheme, testSignal(SeverityLow), nil); err != nil {
		t.Fatal(err)
	}

	// Filtering the same already-resolved source again must not error or re-write - resolveIfOpen
	// is a no-op once VerificationOutcome is already Resolved.
	result, err := Ingest(ctx, c, scheme, testSignal(SeverityLow), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result != ResultFiltered {
		t.Errorf("result = %q, want %q (already resolved - nothing new happened)", result, ResultFiltered)
	}
}

// TestIngest_VerificationTransition_RecordsSeverity proves candor_verification_transitions_total
// carries the finding's severity, not just the outcome - the dashboard's per-severity
// Resolved/Recurred breakdown depends entirely on this label being correct.
func TestIngest_VerificationTransition_RecordsSeverity(t *testing.T) {
	c, scheme := newFakeClient(t, policy("policy", []string{testProvider}, SeverityHigh))
	ctx := context.Background()

	before := testutil.ToFloat64(metrics.VerificationTransitionsTotal.WithLabelValues("still_present", SeverityCritical))
	if _, err := Ingest(ctx, c, scheme, testSignal(SeverityCritical), nil); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(metrics.VerificationTransitionsTotal.WithLabelValues("still_present", SeverityCritical)) - before; got != 1 {
		t.Errorf("still_present/CRITICAL increased by %v, want 1", got)
	}

	// Severity drops below threshold -> resolved. resolveIfOpen must report the finding's last
	// real severity (CRITICAL), not the new signal's (LOW, which didn't clear the policy).
	beforeResolved := testutil.ToFloat64(metrics.VerificationTransitionsTotal.WithLabelValues("resolved", SeverityCritical))
	if _, err := Ingest(ctx, c, scheme, testSignal(SeverityLow), nil); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(metrics.VerificationTransitionsTotal.WithLabelValues("resolved", SeverityCritical)) - beforeResolved; got != 1 {
		t.Errorf("resolved/CRITICAL increased by %v, want 1 (must record the resolved finding's own severity, not the filtered signal's)", got)
	}

	// Recurring at CRITICAL again must record recurred/CRITICAL, not recurred/LOW.
	beforeRecurred := testutil.ToFloat64(metrics.VerificationTransitionsTotal.WithLabelValues("recurred", SeverityCritical))
	if _, err := Ingest(ctx, c, scheme, testSignal(SeverityCritical), nil); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(metrics.VerificationTransitionsTotal.WithLabelValues("recurred", SeverityCritical)) - beforeRecurred; got != 1 {
		t.Errorf("recurred/CRITICAL increased by %v, want 1", got)
	}
}

func TestIngest_Creates_NotifiesWebhook(t *testing.T) {
	url, received := webhookServer(t)
	c, scheme := newFakeClient(t, policyWithWebhook([]string{testProvider}, url))
	sig := testSignal(SeverityCritical)

	if _, err := Ingest(context.Background(), c, scheme, sig, nil); err != nil {
		t.Fatal(err)
	}

	event := waitForNotification(t, received)
	if event.Kind != notify.KindFindingCreated || event.Severity != SeverityCritical {
		t.Errorf("event = %+v, want Kind=%q Severity=%q", event, notify.KindFindingCreated, SeverityCritical)
	}
}

func TestIngest_UpdatedWithoutOutcomeChange_NoNotification(t *testing.T) {
	url, received := webhookServer(t)
	c, scheme := newFakeClient(t, policyWithWebhook([]string{testProvider}, url))
	sig := testSignal(SeverityCritical)
	ctx := context.Background()

	if _, err := Ingest(ctx, c, scheme, sig, nil); err != nil {
		t.Fatal(err)
	}
	waitForNotification(t, received) // drain the FindingCreated notification from the first ingest

	sig.Summary = "updated summary, same severity"
	if _, err := Ingest(ctx, c, scheme, sig, nil); err != nil {
		t.Fatal(err)
	}

	assertNoNotification(t, received)
}

func TestIngest_Resolved_NotifiesWebhook(t *testing.T) {
	url, received := webhookServer(t)
	c, scheme := newFakeClient(t, policyWithWebhook([]string{testProvider}, url))
	ctx := context.Background()

	if _, err := Ingest(ctx, c, scheme, testSignal(SeverityCritical), nil); err != nil {
		t.Fatal(err)
	}
	waitForNotification(t, received) // drain FindingCreated

	if _, err := Ingest(ctx, c, scheme, testSignal(SeverityLow), nil); err != nil {
		t.Fatal(err)
	}

	event := waitForNotification(t, received)
	if event.Kind != notify.KindFindingResolved {
		t.Errorf("event.Kind = %q, want %q", event.Kind, notify.KindFindingResolved)
	}
}

func TestIngest_Recurred_NotifiesWebhook(t *testing.T) {
	url, received := webhookServer(t)
	c, scheme := newFakeClient(t, policyWithWebhook([]string{testProvider}, url))
	ctx := context.Background()

	if _, err := Ingest(ctx, c, scheme, testSignal(SeverityCritical), nil); err != nil {
		t.Fatal(err)
	}
	waitForNotification(t, received) // drain FindingCreated
	if _, err := Ingest(ctx, c, scheme, testSignal(SeverityLow), nil); err != nil {
		t.Fatal(err)
	}
	waitForNotification(t, received) // drain FindingResolved

	if _, err := Ingest(ctx, c, scheme, testSignal(SeverityCritical), nil); err != nil {
		t.Fatal(err)
	}

	event := waitForNotification(t, received)
	if event.Kind != notify.KindFindingRecurred {
		t.Errorf("event.Kind = %q, want %q", event.Kind, notify.KindFindingRecurred)
	}
}

func TestIngest_NoWebhookConfigured_NeverCallsOut(t *testing.T) {
	// No Webhook on the policy at all - Ingest must not attempt any HTTP call. If it tried to
	// reach an unconfigured/empty URL this would fail fast (notify.Send rejects non-http(s) URLs),
	// so a passing Ingest call here is itself the proof.
	c, scheme := newFakeClient(t, policy("policy", []string{testProvider}, SeverityHigh))
	if _, err := Ingest(context.Background(), c, scheme, testSignal(SeverityCritical), nil); err != nil {
		t.Fatal(err)
	}
}

// TestIngest_CostRegression is the design doc's own required check (docs/design.md,
// "Verification"): re-ingesting unchanged content must never look new. There's no LLM call to
// count yet (that's slice 4, gated by exactly this mechanism) - what's provable now, and what
// slice 4's real enrichment gate will be built directly on top of, is that NeedsEnrichment makes
// exactly one true->false transition across N ingests of identical content, and reverses only
// when the content actually changes. If this regresses, slice 4's LLM gating regresses with it.
func TestIngest_CostRegression(t *testing.T) {
	c, scheme := newFakeClient(t, policy("policy", []string{testProvider}, SeverityLow))
	sig := testSignal(SeverityCritical)
	ctx := context.Background()

	getFinding := func() *candorv1alpha1.Finding {
		findings := &candorv1alpha1.FindingList{}
		if err := c.List(ctx, findings); err != nil {
			t.Fatal(err)
		}
		if len(findings.Items) != 1 {
			t.Fatalf("got %d Findings, want exactly 1", len(findings.Items))
		}
		return &findings.Items[0]
	}

	// First ingest of genuinely new content: enrichment is needed.
	if _, err := Ingest(ctx, c, scheme, sig, nil); err != nil {
		t.Fatal(err)
	}
	if !NeedsEnrichment(getFinding()) {
		t.Fatal("a never-enriched Finding must need enrichment")
	}

	// Simulate the (future) slice-4 enrichment reconciler doing its one real piece of work: mark
	// the current fingerprint enriched.
	f := getFinding()
	f.Status.EnrichedFingerprint = f.Status.Fingerprint
	if err := c.Status().Update(ctx, f); err != nil {
		t.Fatal(err)
	}

	// N more ingests of the identical signal. Every single one must report "no enrichment
	// needed" - this is the actual cost claim: unchanged content costs nothing, N times over,
	// not just once.
	const n = 10
	for i := range n {
		if _, err := Ingest(ctx, c, scheme, sig, nil); err != nil {
			t.Fatal(err)
		}
		if NeedsEnrichment(getFinding()) {
			t.Fatalf("iteration %d: unchanged content reported as needing enrichment - this is the exact k8sgpt failure mode (9,300 calls for 164 stable findings) this mechanism exists to prevent", i)
		}
	}

	// Now the content actually changes. This must flip back to true - a suppressed/settled
	// Finding "resurfacing on its own" (pillar 3) depends on this transition being real.
	changed := sig
	changed.Summary = "5 critical vulns now, not 3"
	if _, err := Ingest(ctx, c, scheme, changed, nil); err != nil {
		t.Fatal(err)
	}
	if !NeedsEnrichment(getFinding()) {
		t.Fatal("changed content must need enrichment again, even though this Finding was already enriched once")
	}
}
