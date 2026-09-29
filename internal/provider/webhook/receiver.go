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

// Package webhook is the generic signal receiver (issue #50): tools that don't expose a
// Kubernetes CRD the way Trivy Operator does (SonarQube, Falco, and most of docs/design.md's
// "Falco, Alertmanager, etc." list) can already POST an event on their own, so one receiver with
// one normalized envelope unlocks all of them without a bespoke provider each.
//
// This is the first mechanism in Candor that accepts inbound network input from outside the
// cluster's own RBAC boundary - CRD-watching is cluster-internal and already RBAC-gated, an HTTP
// endpoint is not. It never ships without authentication (issue #51, same PR): an unauthenticated
// receiver that can create Findings is a spoofing vector, not a lesser version of the feature.
//
// No +kubebuilder:rbac markers are added here on purpose - everything this package's Ingest call
// needs (SignalPolicy get/list/watch, Finding create/update/patch + status) is already granted by
// existing markers elsewhere. Secrets access stays deliberately ungranted at cluster scope, same
// as GitOpsRepo.SecretRef - a namespace enabling WebhookReceiver must also grant the controller's
// ServiceAccount a namespaced Role naming that one Secret.
package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
	"github.com/azva-co/candor/internal/metrics"
	"github.com/azva-co/candor/internal/signal"
)

// ProviderName is how this provider identifies itself in Signal.Provider and how a SignalPolicy
// enables it (SignalPolicySpec.Providers).
const ProviderName = "webhook"

// refKindPrefix is a fixed sentinel base for Signal.RefKind. Unlike a CRD-backed provider, a
// webhook delivery isn't read from a real Kubernetes object, so there's nothing more specific to
// name here - Payload.ID (mapped to Signal.RefName) is what gives repeated deliveries about the
// same underlying issue a stable Finding identity (see findingName in internal/signal/ingest.go).
//
// The authenticated policy's name is appended to this prefix, not used bare: findingName hashes
// Provider+RefKind+RefName, and Provider ("webhook") and this constant would otherwise both be
// identical across every delivery regardless of which policy or tool sent it, collapsing Finding
// identity down to whatever the sender happens to put in Payload.ID alone. Two different tools
// behind two different policies in the same namespace picking overlapping ID schemes (small
// sequential integers are a realistic example) would otherwise silently share one Finding object,
// each overwriting the other's Spec and flipping VerificationOutcome for what looks to an operator
// like an unrelated finding from a different tool. Scoping by policy name ties identity to the
// specific endpoint/secret that authenticated the delivery, matching every other place this
// provider already scopes by policy (RestrictToPolicy).
const refKindPrefix = "WebhookEvent"

const signatureHeader = "X-Candor-Signature"

// maxBodyBytes bounds a single request body - generous for a JSON envelope, bounds a naive flood
// from consuming unbounded memory per request.
const maxBodyBytes = 1 << 20 // 1 MiB

// Payload is Candor's own normalized signal envelope - genuinely generic, not a parser per
// upstream tool (docs/design.md, Signal providers). A tool whose native webhook doesn't already
// match this shape needs a small transform in front, the same relay-in-front pattern
// internal/notify's outbound sink already documents for the opposite direction.
type Payload struct {
	// Severity must be exactly one of LOW/MEDIUM/HIGH/CRITICAL (signal.Severity* constants) -
	// checked here, not left to fail silently later: an unrecognised value would never match any
	// SignalPolicy's minSeverity, so the signal would simply vanish with no Finding and no error.
	Severity string `json:"severity"`
	// Kind, Name identify the Kubernetes resource this signal is about.
	Kind string `json:"kind"`
	Name string `json:"name"`
	// Summary is a short, human-readable description - untrusted input, treated as data only
	// (docs/design.md pillar 6, SECURITY.md), never as instructions, same stance as every other
	// provider's signal content.
	Summary string `json:"summary"`
	// ID is the sender's own stable identifier for this event (e.g. a SonarQube issue key, a
	// Falco rule+resource combination). Required - becomes Signal.RefName, and is what makes
	// repeated deliveries about the same underlying issue update one Finding rather than create a
	// new one each time.
	ID string `json:"id"`
}

// Receiver is a manager Runnable (same shape as internal/controller.DigestRunnable - a plain HTTP
// server, not a CRD-triggered reconciler) that accepts inbound signals. Routes resolve to a
// specific SignalPolicy, e.g. POST /webhook/<namespace>/<signalpolicy-name>, since the shared
// secret and any future per-policy config live there.
type Receiver struct {
	client.Client
	Scheme *runtime.Scheme
	// Addr the HTTP server listens on, e.g. ":9444".
	Addr string

	// hmacKeys caches resolved WebhookReceiver Secret data for hmacKeyCacheTTL - see its own doc
	// comment for why. Unexported and zero-value-ready: nothing outside this package constructs
	// or overrides it.
	hmacKeys hmacKeyCache
}

var (
	_ manager.Runnable               = &Receiver{}
	_ manager.LeaderElectionRunnable = &Receiver{}
)

// NeedLeaderElection reports false: this is a stateless HTTP receiver, not a reconciler
// coordinating writes across replicas, so it must run on every replica, not only the leader.
// Without this, controller-runtime's default Runnable dispatch (anything that isn't a
// LeaderElectionRunnable falls into the leader-election group "for backwards compatibility")
// would silently start the receiver only on whichever pod holds the lease - verified against the
// installed controller-runtime's own runnable_group.go before relying on this.
func (r *Receiver) NeedLeaderElection() bool { return false }

// Handler returns the HTTP handler this Receiver serves - exposed separately from Start so tests
// can drive it through a real http.ServeMux (required for req.PathValue to populate) without
// binding an actual port.
func (r *Receiver) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /webhook/{namespace}/{policy}", r.handle)
	return mux
}

func (r *Receiver) Start(ctx context.Context) error {
	log := logf.FromContext(ctx)
	srv := &http.Server{
		Addr:    r.Addr,
		Handler: r.Handler(),
		// ReadHeaderTimeout alone doesn't bound body-read time - a client that sends headers
		// promptly then trickles the body a few bytes at a time would otherwise hold a goroutine
		// open indefinitely (slowloris-shaped), on exactly the component that accepts inbound
		// network input from outside the cluster's own RBAC boundary. ReadTimeout bounds the
		// entire request read (headers + body), not just the headers. WriteTimeout and IdleTimeout
		// close the same class of gap on the write and idle-keepalive sides - a client that reads
		// the response slowly, or not at all, or just holds a keepalive connection open, would
		// otherwise be unbounded there even with the read side fully covered.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       readTimeout,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// A real net.Listen, not http.Server's own ListenAndServe, specifically so the bind itself
	// happens synchronously here, before WebhookReceiverUp is ever set to 1 - ListenAndServe binds
	// and serves in one call, which would mean setting the gauge right after launching it in a
	// goroutine races the bind itself: a port already in use could report "up" for a moment (or
	// longer, under scheduler contention) before the goroutine's own error ever lands, undermining
	// the exact alerting guarantee this gauge exists to provide.
	listener, err := net.Listen("tcp", r.Addr)
	if err != nil {
		log.Error(err, "webhook signal receiver failed to bind - it will not be retried this run")
		return nil
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(listener) }()

	metrics.WebhookReceiverUp.Set(1)
	defer metrics.WebhookReceiverUp.Set(0)

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Logged, not returned - same reasoning as the errCh branch below: a slow-but-otherwise-
		// normal shutdown (an in-flight request still reading a body close to readTimeout when the
		// manager starts a rolling restart, for instance) can make Shutdown itself return
		// context.DeadlineExceeded, and that must not reach the manager's shared error channel any
		// more than a ListenAndServe error should.
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Error(err, "webhook signal receiver did not shut down cleanly within its grace period")
		}
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		// Logged, not returned: a Runnable error here is fatal to the whole manager (verified
		// against controller-runtime's own runnable_group.go - every group shares one errChan
		// that terminates the process), which would take down every unrelated reconciler over a
		// failure isolated to this one HTTP server (e.g. the port already in use). Matches
		// internal/controller.DigestRunnable's own convention (a sibling Runnable, different
		// package): it never returns a non-nil error either.
		log.Error(err, "webhook signal receiver stopped unexpectedly - it will not be retried this run")
		return nil
	}
}

// readTimeout bounds the http.Server's total request read (Start, below) - the connection-level
// deadline this sets runs from request start regardless of when the handler actually calls
// req.Body.Read, which is exactly why handle() reads the body first, before either apiserver call:
// with the body read done immediately, this deadline is never in a race with apiserver latency.
const readTimeout = 15 * time.Second

// handlerTimeout bounds every apiserver call this handler makes directly on its own request's
// context (SignalPolicy Get, Ingest's own List/Get/Update calls), now that the body read (bounded
// separately by readTimeout, above) happens first and no longer shares a budget with them - the
// exact bug this package's own CHANGELOG entry describes (a Secret Get blocking forever with no
// timeout) had no backstop before this; this is that backstop for every other way an apiserver
// call on this path could stall. The Secret resolve on a cache miss deliberately does NOT share
// this budget - see secretResolveTimeout.
const handlerTimeout = 10 * time.Second

// secretResolveTimeout bounds the Secret Get a cache miss in hmacKeyCache triggers - deliberately
// independent of any one request's own remaining handlerTimeout budget, not a derived fraction of
// it. Singleflight coalesces concurrent misses onto whichever request happens to become the
// leader (see hmacKeyCache's doc comment); tying this to that leader's own remaining time would
// make every other request coalesced onto it fail or succeed based on how much budget a
// completely unrelated request happened to have left, rather than on its own. A fixed, modest
// timeout dedicated to this one apiserver round trip avoids that, while still leaving headroom
// under the http.Server's own WriteTimeout even in the worst case where the SignalPolicy Get
// above consumed nearly all of handlerTimeout first.
const secretResolveTimeout = 5 * time.Second

func (r *Receiver) handle(w http.ResponseWriter, req *http.Request) {
	log := logf.FromContext(req.Context())

	namespace := req.PathValue("namespace")
	policyName := req.PathValue("policy")

	// Cheap and early, before reading anything: a sender that declares an oversized body up front
	// is rejected without even attempting to read it. Not a substitute for the LimitReader check
	// below - Content-Length can be absent or wrong (chunked transfer encoding doesn't set it at
	// all) - just an optimization for the common case where it's present and honest.
	if req.ContentLength > maxBodyBytes {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	// Read the body before either apiserver call below, not after: http.Server's ReadTimeout is a
	// connection-level deadline running from request start, not from whenever this handler gets
	// around to calling req.Body.Read - apiserver latency spent on a Get first would eat into the
	// same budget the body read itself needs, and a legitimate, promptly-sent small body could
	// fail with a spurious read timeout under nothing worse than ordinary apiserver slowness. One
	// byte past the limit, to detect truncation explicitly rather than silently signing a
	// truncated body: a legitimate request over the limit would otherwise fail signature
	// verification against its own (untruncated) signature and surface as a misleading 401,
	// sending whoever debugs it chasing an auth problem that's actually an undetected size cap.
	body, err := io.ReadAll(io.LimitReader(req.Body, maxBodyBytes+1))
	if err != nil {
		http.Error(w, "reading request body", http.StatusBadRequest)
		return
	}
	if len(body) > maxBodyBytes {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	// Created here, not at the top of this function: it must bound only the apiserver calls from
	// this point on (SignalPolicy Get, Secret Get, Ingest's own calls), fresh, not shared with
	// whatever time the body read above happened to take - creating it before the read would put
	// it right back in a race with readTimeout, the exact thing reading the body first is meant to
	// avoid.
	ctx, cancel := context.WithTimeout(req.Context(), handlerTimeout)
	defer cancel()

	policy := &candorv1alpha1.SignalPolicy{}
	err = r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: policyName}, policy)
	// A transient apiserver problem (throttled, momentarily unreachable) is a genuinely different
	// case from "this policy doesn't exist" and gets a different response - a sender that retries
	// on 5xx but not on 404 (a common client convention) would otherwise drop the signal
	// permanently on nothing worse than backend hiccup. Only logged here too, for the same reason.
	if err != nil && !apierrors.IsNotFound(err) {
		log.Error(err, "getting SignalPolicy for webhook receiver", "namespace", namespace, "signalpolicy", policyName)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// A missing policy and a policy with no WebhookReceiver configured get the identical response -
	// not distinguishing the two avoids letting a caller enumerate which SignalPolicy names exist
	// in a namespace by probing this endpoint. The second case is also the fail-closed guarantee:
	// no WebhookReceiver configured means this policy's endpoint always rejects, never "unlimited"
	// - see WebhookReceiver's doc comment for why this is the one guardrail in Candor that must
	// never default to allow.
	if err != nil || policy.Spec.WebhookReceiver == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	secretKey := client.ObjectKey{Namespace: namespace, Name: policy.Spec.WebhookReceiver.SecretRef.Name}
	// Cached (with concurrent-miss coalescing - see hmacKeyCache's doc comment) rather than
	// resolved against the apiserver on every request: bounds the apiserver load a flood of POSTs
	// against this route can generate, including ones that will fail signature verification below
	// regardless (the Secret still has to be read first).
	//
	// A misconfigured secret (missing, wrong key) and an actually-wrong signature both surface as
	// the same 401 response - deliberately not distinguishing "your signature is wrong" from "the
	// operator's own secret is broken", for the same enumeration-avoidance reasoning as above. The
	// real cause is still logged server-side. A misconfigured secret is also never cached, so a
	// fix takes effect on the very next request rather than waiting out the TTL.
	hmacKey, err := r.hmacKeys.getOrResolve(ctx, secretKey, func() ([]byte, error) {
		// A context of its own, bound by secretResolveTimeout - not this request's ctx, and not
		// derived from it either. Singleflight runs this closure at most once per set of
		// concurrent misses and shares its result (success or failure) with every caller waiting
		// on it (see hmacKeyCache's doc comment): whichever request happens to become the leader
		// here is arbitrary, so tying this call's deadline to that one request's own remaining
		// budget would make every other coalesced request's outcome depend on a completely
		// unrelated request's timeline rather than its own - see secretResolveTimeout's own doc
		// comment for the full reasoning.
		resolveCtx, cancel := context.WithTimeout(context.Background(), secretResolveTimeout)
		defer cancel()
		return signal.ResolveSecretKey(resolveCtx, r.Client, secretKey, "secret")
	})
	if err != nil {
		log.Error(err, "resolving WebhookReceiver secret", "secret", secretKey)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if !validSignature(hmacKey, body, req.Header.Get(signatureHeader)) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var payload Payload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if err := validatePayload(payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sig := signal.Signal{
		Provider:  ProviderName,
		Severity:  payload.Severity,
		Namespace: namespace,
		Kind:      payload.Kind,
		Name:      payload.Name,
		Summary:   payload.Summary,
		RefKind:   refKindPrefix + "/" + policyName,
		RefName:   payload.ID,
		// Scopes acceptance/routing to exactly the policy that authenticated this request - see
		// Signal.RestrictToPolicy's doc comment for why the namespace-wide default would otherwise
		// let a signal authenticated against one policy's secret be accepted (or routed) by a
		// different, laxer policy in the same namespace.
		RestrictToPolicy: policy,
	}

	// owner is nil: unlike a CRD-backed provider, there's no persistent Kubernetes object behind
	// a webhook delivery to own the resulting Finding, so it won't be garbage-collected the way a
	// Trivy-sourced one is when its VulnerabilityReport is deleted - a real, documented consequence
	// of accepting external signals, not an oversight.
	result, err := signal.Ingest(ctx, r.Client, r.Scheme, sig, nil)
	if err != nil {
		log.Error(err, "ingesting webhook signal", "namespace", namespace, "signalpolicy", policyName)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.V(1).Info("Ingested webhook signal", "result", result, "severity", sig.Severity, "resource", namespace+"/"+sig.Name)
	// 202 either way - a filtered/resolved result isn't necessarily a misconfiguration (e.g.
	// severity legitimately below this policy's own threshold), so it isn't treated as an error.
	// The result is still reported in the body, not swallowed, so an integrator that wants to
	// notice "this policy doesn't actually enable the webhook provider" can check it rather than
	// only ever seeing an opaque success.
	responseBody, err := json.Marshal(struct {
		Result signal.Result `json:"result"`
	}{Result: result})
	if err != nil {
		// signal.Result is always one of a handful of plain string constants - Marshal cannot
		// fail on it in practice, but every other JSON-producing call site in this codebase
		// (internal/notify, internal/llm/anthropic, internal/llm/ollama) checks its own error
		// rather than assuming, so this does too rather than being the one exception.
		log.Error(err, "marshaling response body")
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write(responseBody)
}

// validSignature checks header against "sha256=<hex-encoded HMAC-SHA256 of body>", the
// GitHub/Stripe convention - signing the body protects integrity in transit, not just possession
// of the key. Uses hmac.Equal (constant-time), never a plain == comparison, which would be a
// timing side-channel.
func validSignature(key, body []byte, header string) bool {
	const prefix = "sha256="
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	got, err := hex.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}

// validSeverities is the single source of truth for the accepted values below - built from
// signal.Severity* directly so the check and its own error message can never drift apart the way
// a separately hand-written message string could.
var validSeverities = []string{signal.SeverityLow, signal.SeverityMedium, signal.SeverityHigh, signal.SeverityCritical}

func validatePayload(p Payload) error {
	if !slices.Contains(validSeverities, p.Severity) {
		return fmt.Errorf("severity must be one of %s, got %q", strings.Join(validSeverities, ", "), p.Severity)
	}
	if p.Kind == "" {
		return errors.New("kind is required")
	}
	if p.Name == "" {
		return errors.New("name is required")
	}
	if p.ID == "" {
		return errors.New("id is required")
	}
	return nil
}
