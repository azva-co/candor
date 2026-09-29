/*
Copyright 2026 Albert Asawaroengchai.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
	"github.com/azva-co/candor/internal/metrics"
)

const (
	testNamespace      = "default"
	testPolicyName     = "policy"
	testSecretName     = "webhook-secret"
	testHMACKey        = "s3cr3t"
	testMinSeverityLow = "LOW"
)

func sign(key, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// newTestFakeClient builds the scheme and fake client shared by every test Receiver in this
// package - newTestReceiver below, and newCountingTestReceiver in hmackeycache_test.go, which
// wraps this same client in an interceptor rather than duplicating its construction.
func newTestFakeClient(t *testing.T, objs ...client.Object) (client.WithWatch, *runtime.Scheme) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&candorv1alpha1.Finding{}).WithObjects(objs...).Build()
	return c, scheme
}

func newTestReceiver(t *testing.T, objs ...client.Object) *Receiver {
	t.Helper()
	c, scheme := newTestFakeClient(t, objs...)
	return &Receiver{Client: c, Scheme: scheme}
}

func withWebhookReceiver() *candorv1alpha1.SignalPolicy {
	return &candorv1alpha1.SignalPolicy{
		Name: testPolicyName, Namespace: testNamespace,
		Spec: candorv1alpha1.SignalPolicySpec{
			Providers:   []string{ProviderName},
			MinSeverity: testMinSeverityLow,
			WebhookReceiver: &candorv1alpha1.WebhookReceiver{
				SecretRef: corev1.LocalObjectReference{Name: testSecretName},
			},
		},
	}
}

func testSecret() *corev1.Secret {
	return &corev1.Secret{
		Name: testSecretName, Namespace: testNamespace,
		Data: map[string][]byte{"secret": []byte(testHMACKey)},
	}
}

const validBody = `{"severity":"HIGH","kind":"Deployment","name":"api","summary":"something's wrong","id":"issue-1"}`

func doRequest(t *testing.T, r *Receiver, policy string, body []byte, sig string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/webhook/"+testNamespace+"/"+policy, bytes.NewReader(body))
	if sig != "" {
		req.Header.Set(signatureHeader, sig)
	}
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, req)
	return rec
}

func TestReceiver_NoWebhookReceiverConfigured_RejectsClosed(t *testing.T) {
	policy := &candorv1alpha1.SignalPolicy{
		Name: testPolicyName, Namespace: testNamespace,
		Spec: candorv1alpha1.SignalPolicySpec{Providers: []string{ProviderName}},
	}
	r := newTestReceiver(t, policy)

	rec := doRequest(t, r, testPolicyName, []byte(validBody), sign([]byte(testHMACKey), []byte(validBody)))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d - no WebhookReceiver configured must fail closed", rec.Code, http.StatusNotFound)
	}
}

func TestReceiver_NonexistentPolicy_SameResponseAsUnconfigured(t *testing.T) {
	r := newTestReceiver(t)

	rec := doRequest(t, r, "does-not-exist", []byte(validBody), "sha256=whatever")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestReceiver_MissingSignatureHeader_Unauthorized(t *testing.T) {
	r := newTestReceiver(t, withWebhookReceiver(), testSecret())

	rec := doRequest(t, r, testPolicyName, []byte(validBody), "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestReceiver_WrongSignature_Unauthorized(t *testing.T) {
	r := newTestReceiver(t, withWebhookReceiver(), testSecret())

	rec := doRequest(t, r, testPolicyName, []byte(validBody), sign([]byte("wrong-key"), []byte(validBody)))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestReceiver_TamperedBody_SignatureNoLongerMatches(t *testing.T) {
	r := newTestReceiver(t, withWebhookReceiver(), testSecret())

	sig := sign([]byte(testHMACKey), []byte(validBody))
	tampered := []byte(`{"severity":"CRITICAL","kind":"Deployment","name":"api","summary":"something's wrong","id":"issue-1"}`)

	rec := doRequest(t, r, testPolicyName, tampered, sig)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d - a signature computed over the original body must not validate a tampered one", rec.Code, http.StatusUnauthorized)
	}
}

func TestReceiver_MisconfiguredSecret_Unauthorized(t *testing.T) {
	// WebhookReceiver configured, but the Secret it names doesn't exist.
	r := newTestReceiver(t, withWebhookReceiver())

	rec := doRequest(t, r, testPolicyName, []byte(validBody), sign([]byte(testHMACKey), []byte(validBody)))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestReceiver_InvalidPayload_BadRequest(t *testing.T) {
	r := newTestReceiver(t, withWebhookReceiver(), testSecret())

	tests := []struct {
		name string
		body string
	}{
		{"unrecognised severity", `{"severity":"YIKES","kind":"Deployment","name":"api","id":"x"}`},
		{"missing kind", `{"severity":"HIGH","name":"api","id":"x"}`},
		{"missing name", `{"severity":"HIGH","kind":"Deployment","id":"x"}`},
		{"missing id", `{"severity":"HIGH","kind":"Deployment","name":"api"}`},
		{"not json", `not json at all`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte(tt.body)
			rec := doRequest(t, r, testPolicyName, body, sign([]byte(testHMACKey), body))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestReceiver_ValidRequest_CreatesFinding(t *testing.T) {
	r := newTestReceiver(t, withWebhookReceiver(), testSecret())

	body := []byte(validBody)
	rec := doRequest(t, r, testPolicyName, body, sign([]byte(testHMACKey), body))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	if got := rec.Body.String(); !strings.Contains(got, `"result":"created"`) {
		t.Errorf("response body = %q, want it to report the actual Ingest result, not just a bare 202", got)
	}

	findings := &candorv1alpha1.FindingList{}
	if err := r.List(t.Context(), findings); err != nil {
		t.Fatal(err)
	}
	if len(findings.Items) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings.Items))
	}
	f := findings.Items[0]
	if f.Spec.Source.Provider != ProviderName {
		t.Errorf("Provider = %q, want %q", f.Spec.Source.Provider, ProviderName)
	}
	if f.Spec.Severity != "HIGH" {
		t.Errorf("Severity = %q, want %q", f.Spec.Severity, "HIGH")
	}
	wantRefKind := refKindPrefix + "/" + testPolicyName
	if f.Spec.Source.RefKind != wantRefKind {
		t.Errorf("RefKind = %q, want %q", f.Spec.Source.RefKind, wantRefKind)
	}
	if f.Spec.Source.RefName != "issue-1" {
		t.Errorf("RefName = %q, want %q", f.Spec.Source.RefName, "issue-1")
	}
	if len(f.OwnerReferences) != 0 {
		t.Errorf("OwnerReferences = %v, want none - a webhook signal has no Kubernetes object to own it", f.OwnerReferences)
	}
}

func TestReceiver_NeedLeaderElection_False(t *testing.T) {
	r := &Receiver{}
	if r.NeedLeaderElection() {
		t.Error("NeedLeaderElection() = true, want false - a stateless HTTP receiver must run on every replica, not only the leader")
	}
}

// TestReceiver_StartFailsToBind_ReturnsNilNotError is the regression test for a real bug found via
// /code-review high: controller-runtime propagates any non-nil Runnable.Start error into the
// manager's single shared error channel, terminating the whole process - a port-bind failure
// isolated to this one HTTP server would otherwise crash every unrelated reconciler with it.
// internal/controller.DigestRunnable in this same package never returns a non-nil error either;
// this proves Receiver now matches that convention.
func TestReceiver_StartFailsToBind_ReturnsNilNotError(t *testing.T) {
	// Occupy a port first so the Receiver's own bind attempt on it fails.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	r := &Receiver{Addr: ln.Addr().String()}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := r.Start(ctx); err != nil {
		t.Errorf("Start() = %v, want nil even when the port is already bound - a Runnable error here is fatal to the whole manager, not just this receiver", err)
	}
	if got := testutil.ToFloat64(metrics.WebhookReceiverUp); got != 0 {
		t.Errorf("WebhookReceiverUp = %v, want 0 - a bind failure is otherwise invisible (Start never returns an error), so this gauge is the thing to alert on", got)
	}
}

// TestReceiver_Start_MetricReflectsRunningState is the regression test for a real finding: Start
// never returning an error (necessary - see TestReceiver_StartFailsToBind_ReturnsNilNotError)
// means a dead receiver was otherwise invisible, with only a log line marking it and the manager's
// own healthz/readyz staying green regardless. WebhookReceiverUp is the alertable signal instead.
func TestReceiver_Start_MetricReflectsRunningState(t *testing.T) {
	r := &Receiver{Addr: "127.0.0.1:0"}
	ctx, cancel := context.WithCancel(context.Background())

	started := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		close(started)
		_ = r.Start(ctx)
		close(stopped)
	}()
	<-started

	deadline := time.After(2 * time.Second)
	for testutil.ToFloat64(metrics.WebhookReceiverUp) != 1 {
		select {
		case <-deadline:
			t.Fatal("WebhookReceiverUp never reached 1 after starting")
		case <-time.After(10 * time.Millisecond):
		}
	}

	cancel()
	<-stopped

	if got := testutil.ToFloat64(metrics.WebhookReceiverUp); got != 0 {
		t.Errorf("WebhookReceiverUp = %v, want 0 after a clean shutdown", got)
	}
}

// TestReceiver_OversizedBody_KnownContentLength_RejectedEarly covers the cheap fast path: a
// sender that declares an oversized body via Content-Length is rejected before anything else runs.
func TestReceiver_OversizedBody_KnownContentLength_RejectedEarly(t *testing.T) {
	r := newTestReceiver(t, withWebhookReceiver(), testSecret())

	oversized := []byte(`{"severity":"HIGH","kind":"Deployment","name":"api","id":"x","summary":"` + strings.Repeat("a", maxBodyBytes) + `"}`)
	rec := doRequest(t, r, testPolicyName, oversized, sign([]byte(testHMACKey), oversized))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d - an oversized body must be rejected explicitly, not silently truncated then fail signature verification as a misleading 401", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

// TestReceiver_OversizedBody_UnknownContentLength_RejectedNotTruncated is the regression test that
// actually exercises the io.LimitReader truncation-detection logic: TestReceiver_OversizedBody_
// KnownContentLength_RejectedEarly above never reaches it, since httptest.NewRequest auto-populates
// Content-Length from a *bytes.Reader body and the cheap early check catches it first. Wrapping the
// reader so that auto-detection doesn't apply (as chunked transfer encoding would look to the
// server - Content-Length genuinely unknown) forces the request past that check and into the
// LimitReader path this test is actually meant to cover.
func TestReceiver_OversizedBody_UnknownContentLength_RejectedNotTruncated(t *testing.T) {
	r := newTestReceiver(t, withWebhookReceiver(), testSecret())

	oversized := []byte(`{"severity":"HIGH","kind":"Deployment","name":"api","id":"x","summary":"` + strings.Repeat("a", maxBodyBytes) + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/webhook/"+testNamespace+"/"+testPolicyName, io.NopCloser(bytes.NewReader(oversized)))
	if req.ContentLength > 0 {
		t.Fatalf("test setup: ContentLength = %d, want unknown (<=0) to actually exercise the LimitReader path", req.ContentLength)
	}
	req.Header.Set(signatureHeader, sign([]byte(testHMACKey), oversized))
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d - an oversized body must be rejected explicitly, not silently truncated then fail signature verification as a misleading 401", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestReceiver_RestrictsToAuthenticatedPolicy_IgnoresLaxerSibling(t *testing.T) {
	// A second, laxer policy in the same namespace enables webhook at LOW with a different secret.
	// A request authenticated against the strict policy's own secret must not be accepted just
	// because the lax policy would have taken it - the regression this receiver-level test covers
	// for the wiring; internal/signal's own test covers the Ingest-level mechanism directly.
	lax := &candorv1alpha1.SignalPolicy{
		Name: "lax", Namespace: testNamespace,
		Spec: candorv1alpha1.SignalPolicySpec{
			Providers:   []string{ProviderName},
			MinSeverity: testMinSeverityLow,
		},
	}
	strict := &candorv1alpha1.SignalPolicy{
		Name: testPolicyName, Namespace: testNamespace,
		Spec: candorv1alpha1.SignalPolicySpec{
			Providers:   []string{ProviderName},
			MinSeverity: "CRITICAL",
			WebhookReceiver: &candorv1alpha1.WebhookReceiver{
				SecretRef: corev1.LocalObjectReference{Name: testSecretName},
			},
		},
	}
	r := newTestReceiver(t, strict, lax, testSecret())

	lowSeverityBody := []byte(`{"severity":"LOW","kind":"Deployment","name":"api","summary":"x","id":"issue-1"}`)
	rec := doRequest(t, r, testPolicyName, lowSeverityBody, sign([]byte(testHMACKey), lowSeverityBody))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	if got := rec.Body.String(); !strings.Contains(got, `"result":"filtered"`) {
		t.Errorf("response body = %q, want %q - a LOW signal authenticated against the CRITICAL-only policy must be filtered, not accepted via the sibling \"lax\" policy", got, `"result":"filtered"`)
	}

	findings := &candorv1alpha1.FindingList{}
	if err := r.List(t.Context(), findings); err != nil {
		t.Fatal(err)
	}
	if len(findings.Items) != 0 {
		t.Errorf("got %d findings, want 0 - the laxer sibling policy must not have accepted this on the strict policy's behalf", len(findings.Items))
	}
}

func TestReceiver_RepeatedDeliverySameID_UpdatesOneFinding(t *testing.T) {
	r := newTestReceiver(t, withWebhookReceiver(), testSecret())

	body := []byte(validBody)
	sig := sign([]byte(testHMACKey), body)
	doRequest(t, r, testPolicyName, body, sig)
	doRequest(t, r, testPolicyName, body, sig)

	findings := &candorv1alpha1.FindingList{}
	if err := r.List(t.Context(), findings); err != nil {
		t.Fatal(err)
	}
	if len(findings.Items) != 1 {
		t.Fatalf("got %d findings after two identical deliveries, want 1", len(findings.Items))
	}
}

// TestReceiver_SamePayloadIDDifferentPolicies_DoNotCollide is the regression test for a real
// finding: Provider ("webhook") and refKindPrefix were both fixed constants, so Finding identity
// collapsed to Payload.ID alone with no per-policy component. Two different tools behind two
// different SignalPolicies picking the same ID (a realistic case - small sequential integers are a
// common ID scheme) would otherwise silently share one Finding, each overwriting the other's Spec.
func TestReceiver_SamePayloadIDDifferentPolicies_DoNotCollide(t *testing.T) {
	const otherPolicyName = "other-policy"
	const otherSecretName = "other-secret"
	const otherHMACKey = "other-key"

	otherPolicy := &candorv1alpha1.SignalPolicy{
		Name: otherPolicyName, Namespace: testNamespace,
		Spec: candorv1alpha1.SignalPolicySpec{
			Providers:   []string{ProviderName},
			MinSeverity: testMinSeverityLow,
			WebhookReceiver: &candorv1alpha1.WebhookReceiver{
				SecretRef: corev1.LocalObjectReference{Name: otherSecretName},
			},
		},
	}
	otherSecret := &corev1.Secret{
		Name: otherSecretName, Namespace: testNamespace,
		Data: map[string][]byte{"secret": []byte(otherHMACKey)},
	}
	r := newTestReceiver(t, withWebhookReceiver(), testSecret(), otherPolicy, otherSecret)

	// Same body (same "id":"issue-1"), delivered to two different policies.
	body := []byte(validBody)
	doRequest(t, r, testPolicyName, body, sign([]byte(testHMACKey), body))
	doRequest(t, r, otherPolicyName, body, sign([]byte(otherHMACKey), body))

	findings := &candorv1alpha1.FindingList{}
	if err := r.List(t.Context(), findings); err != nil {
		t.Fatal(err)
	}
	if len(findings.Items) != 2 {
		t.Fatalf("got %d findings, want 2 - the same sender-supplied id from two different policies must not collide into one Finding", len(findings.Items))
	}
}

// TestReceiver_SlowOutboundWebhook_DoesNotBlockResponse is the regression test for issue #63:
// internal/signal.Ingest used to send a policy's own outbound Spec.Webhook notification (a
// completely separate concept from this policy's inbound WebhookReceiver) synchronously before
// returning, so a slow or unreachable notification endpoint held up the HTTP response to whoever
// POSTed the original signal - a caller that never even observes that notification's outcome.
func TestReceiver_SlowOutboundWebhook_DoesNotBlockResponse(t *testing.T) {
	// The outbound notification handler blocks on release, held open indefinitely rather than for
	// a fixed sleep - the assertion below only needs the response to return before this handler
	// ever completes, not before some specific duration elapses, so there's no delay value to
	// tune. release is closed explicitly, further down, before this function returns - not via
	// defer: defers run LIFO, so a deferred close(release) registered before the deferred
	// slowNotify.Close() below would run AFTER it, and Close() itself blocks until every
	// outstanding request on the server completes - exactly the request this handler is still
	// holding open on <-release, deadlocking the whole test.
	release := make(chan struct{})
	notifyReached := make(chan struct{}, 1)
	slowNotify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		notifyReached <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer slowNotify.Close()

	policy := withWebhookReceiver()
	policy.Spec.Webhook = &candorv1alpha1.Webhook{URL: slowNotify.URL}
	r := newTestReceiver(t, policy, testSecret())

	body := []byte(validBody)
	start := time.Now()
	rec := doRequest(t, r, testPolicyName, body, sign([]byte(testHMACKey), body))
	elapsed := time.Since(start)

	// Unblocked unconditionally, before any assertion that could call t.Fatal: a Fatal here would
	// still run the deferred slowNotify.Close() (t.Fatal uses runtime.Goexit, not a panic that
	// skips deferred calls), which would deadlock exactly as described above if release were
	// still open when it ran.
	close(release)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	// 1s, not a tighter bound: the outbound notification handler is held open indefinitely (not
	// for some short fixed delay), so this only needs enough headroom to absorb ordinary -race/CI
	// scheduling delay without becoming a flake source, matching the slack this package's other
	// timing-sensitive tests already use for the same reason.
	const wantUnder = 1 * time.Second
	if elapsed >= wantUnder {
		t.Errorf("handler took %v to respond, want well under %v - the outbound notification handler was still blocked at that point, so the response must not have waited on it at all", elapsed, wantUnder)
	}

	select {
	case <-notifyReached:
	case <-time.After(2 * time.Second):
		t.Error("outbound notification endpoint was never reached - the async send may not have fired at all")
	}
}
