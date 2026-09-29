package signal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
	"github.com/azva-co/candor/internal/metrics"
	"github.com/azva-co/candor/internal/notify"
)

// Result reports what Ingest did, so callers (and tests) can observe the outcome without Ingest
// depending on a particular logger.
type Result string

const (
	// ResultCreated means a new Finding was created.
	ResultCreated Result = "created"
	// ResultUpdated means an existing Finding was brought up to date.
	ResultUpdated Result = "updated"
	// ResultUnchanged means an existing Finding already matched - no write happened.
	ResultUnchanged Result = "unchanged"
	// ResultFiltered means no Finding was produced: either no SignalPolicy in the signal's
	// namespace enables this provider, or the signal's severity is below every policy that does.
	// No Finding previously existed for this source either - there was nothing to resolve.
	ResultFiltered Result = "filtered"
	// ResultResolved means the signal was filtered (same reasons as ResultFiltered), but a
	// previously-open Finding existed for this exact source - it has been marked Resolved rather
	// than left stale. See Finding.Status.VerificationOutcome.
	ResultResolved Result = "resolved"
)

// Ingest is the single path from a Signal to a Finding. It looks up whether any SignalPolicy in
// the signal's own namespace opts into this provider at this severity (SignalPolicy governs
// signals in its own namespace only - same convention as ResourceQuota/NetworkPolicy, not a
// separate namespace-selector field), and if so, creates or updates the corresponding Finding.
//
// owner becomes the Finding's owner reference (e.g. the originating VulnerabilityReport), so the
// Finding is garbage-collected automatically when its source signal object is deleted.
func Ingest(ctx context.Context, c client.Client, scheme *runtime.Scheme, sig Signal, owner client.Object) (Result, error) {
	relevantPolicies, err := listRelevantPolicies(ctx, c, sig)
	if err != nil {
		return "", err
	}

	if !anyPolicyAccepts(relevantPolicies, sig) {
		// One Get, reused for both the existence check and (if warranted) the resolve write below
		// - not a separate existence check followed by a second Get on the same object. Most
		// filtered signals from a chatty source have no open Finding at all, and this Get is far
		// cheaper than the namespace-wide List the broader check below requires, so it's worth
		// doing first regardless.
		findingKey := client.ObjectKey{Namespace: sig.Namespace, Name: findingName(sig)}
		existing := &candorv1alpha1.Finding{}
		if err := c.Get(ctx, findingKey, existing); err != nil {
			if apierrors.IsNotFound(err) {
				return ResultFiltered, nil
			}
			return "", fmt.Errorf("getting Finding %s: %w", findingKey, err)
		}
		if existing.Status.VerificationOutcome == VerificationResolved {
			return ResultFiltered, nil
		}

		// Whether to actually RESOLVE an existing Finding must never be narrowed to just the
		// policy this particular request authenticated against: findingName has no policy
		// component in general, so a Finding is namespace-wide, shared by every policy that could
		// produce it - a different, still-active sibling policy's ongoing interest in it must not
		// be overridden just because this one request's authorization happens to be scoped
		// narrower. Re-check against every policy in the namespace before resolving anything.
		//
		// Provably redundant for the only current caller, kept anyway: the webhook receiver
		// happens to fold its own policy name into RefKind (see refKindPrefix's doc comment), so a
		// Finding this branch would ever fetch could only have been produced by the very policy
		// already being checked - no sibling policy's key could collide with it. But that's a fact
		// about one caller's current RefKind construction, not something Ingest should have to
		// know or assume to stay correct; coupling this safety net to it would mean a future
		// change to that construction (or a second RestrictToPolicy-setting provider that doesn't
		// scope RefKind the same way) silently reintroduces the original bug with nothing left to
		// catch it. The extra List only runs on an already-uncommon path (filtered signal, Finding
		// still open), so the cost of keeping it is small next to what removing it would risk.
		resolutionPolicies := relevantPolicies
		if sig.RestrictToPolicy != nil {
			resolutionPolicies, err = listNamespacePolicies(ctx, c, sig.Namespace)
			if err != nil {
				return "", err
			}
			if anyPolicyAccepts(resolutionPolicies, sig) {
				// Some other policy in the namespace still accepts this content - not this
				// request's call to resolve a Finding that policy still considers open.
				return ResultFiltered, nil
			}
		}

		// existing.Spec.Severity is still the last real severity before this resolution - only
		// Status is touched below, so this reports what was resolved, not the filtered-out signal
		// that triggered the resolution (which may have no severity at all, e.g. a Trivy report
		// that dropped to zero vulnerabilities).
		severity := existing.Spec.Severity
		existing.Status.VerificationOutcome = VerificationResolved
		if err := c.Status().Update(ctx, existing); err != nil {
			return "", fmt.Errorf("resolving Finding %s: %w", findingKey, err)
		}
		metrics.VerificationTransitionsTotal.WithLabelValues(verificationMetricLabel[VerificationResolved], severity).Inc()
		if webhook := webhookFor(resolutionPolicies, sig.Provider); webhook != nil {
			notifyEvent(ctx, webhook.URL, notify.KindFindingResolved, existing)
		}
		return ResultResolved, nil
	}

	finding := &candorv1alpha1.Finding{
		Name:      findingName(sig),
		Namespace: sig.Namespace,
	}

	result, err := controllerutil.CreateOrUpdate(ctx, c, finding, func() error {
		finding.Spec = candorv1alpha1.FindingSpec{
			Source: candorv1alpha1.FindingSource{
				Provider: sig.Provider,
				Kind:     sig.Kind,
				Name:     sig.Name,
				RefKind:  sig.RefKind,
				RefName:  sig.RefName,
			},
			Severity: sig.Severity,
			Summary:  sig.Summary,
		}
		if owner != nil {
			return controllerutil.SetOwnerReference(owner, finding, scheme)
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("upserting Finding %s/%s: %w", sig.Namespace, finding.Name, err)
	}

	// Fingerprint and VerificationOutcome are status fields, and status is a separate subresource
	// on Finding - the CreateOrUpdate above never persists them, so they need their own write.
	// Skipped entirely when neither actually changes, both to avoid a needless resourceVersion
	// bump on every reconcile of truly unchanged content, and because that "no write for no
	// change" property is the same cost-consciousness this whole mechanism enforces on the LLM
	// call Fingerprint gates.
	//
	// previousOutcome is read here, before either field is overwritten below - finding.Status is
	// whatever CreateOrUpdate fetched from the API (its mutate closure above only touched .Spec),
	// so on a brand new Finding this is the zero value, and on an existing one it's the outcome
	// from the last time Ingest ran.
	previousOutcome := finding.Status.VerificationOutcome
	newOutcome := VerificationStillPresent
	if previousOutcome == VerificationResolved {
		newOutcome = VerificationRecurred
	}

	fp := Fingerprint(sig)
	fingerprintChanged := finding.Status.Fingerprint != fp
	outcomeChanged := finding.Status.VerificationOutcome != newOutcome

	if fingerprintChanged {
		finding.Status.Fingerprint = fp
	}
	if outcomeChanged {
		finding.Status.VerificationOutcome = newOutcome
		metrics.VerificationTransitionsTotal.WithLabelValues(verificationMetricLabel[newOutcome], sig.Severity).Inc()
	}
	if fingerprintChanged || outcomeChanged {
		if err := c.Status().Update(ctx, finding); err != nil {
			return "", fmt.Errorf("updating status on Finding %s/%s: %w", sig.Namespace, finding.Name, err)
		}
	}

	var finalResult Result
	switch result {
	case controllerutil.OperationResultCreated:
		finalResult = ResultCreated
	case controllerutil.OperationResultUpdated:
		finalResult = ResultUpdated
	default:
		finalResult = ResultUnchanged
	}

	// Notify on a brand new Finding, or on an existing one recurring - not on every routine
	// content refresh (ResultUpdated with no outcome change) or unchanged reconcile, which would
	// just be noise.
	if webhook := webhookFor(relevantPolicies, sig.Provider); webhook != nil {
		switch {
		case finalResult == ResultCreated:
			notifyEvent(ctx, webhook.URL, notify.KindFindingCreated, finding)
		case outcomeChanged && newOutcome == VerificationRecurred:
			notifyEvent(ctx, webhook.URL, notify.KindFindingRecurred, finding)
		}
	}

	return finalResult, nil
}

// webhookFor returns the Webhook configured by the first policy in policies that enables
// provider, or nil if none is configured. Reuses the policies slice Ingest already fetched,
// rather than issuing a second List - the same "first policy for this provider governs shared
// config" convention CheckBudget's caller already relies on for Budget.
func webhookFor(policies []candorv1alpha1.SignalPolicy, provider string) *candorv1alpha1.Webhook {
	for i := range policies {
		if providerEnabled(policies[i].Spec.Providers, provider) && policies[i].Spec.Webhook != nil {
			return policies[i].Spec.Webhook
		}
	}
	return nil
}

// notifyEvent sends a Finding notification best-effort: a failure is logged and counted, never
// returned as an error - a broken webhook endpoint must not make Finding reconciliation fail.
//
// Queued onto notify's shared async worker pool, not sent inline (issue #63): the caller that
// triggered this Ingest - an HTTP request for the webhook signal receiver, a reconcile for
// Trivy's - must never wait on a slow or unreachable notification endpoint for a side effect
// whose outcome it never observes anyway, most consequential for the webhook receiver
// specifically, where that caller is the sender's own HTTP request. SendAsync's own bounded pool
// (shared with internal/controller.DigestRunnable's digest sends) caps how many of these can run
// concurrently across the whole process, rather than this spawning an unbounded goroutine per
// notification the way a bare `go func()` here would.
func notifyEvent(ctx context.Context, url, kind string, f *candorv1alpha1.Finding) {
	log := logf.FromContext(ctx)
	name := f.Name
	event := notify.Event{
		Kind: kind, Namespace: f.Namespace, Finding: name,
		Severity: f.Spec.Severity, Summary: f.Spec.Summary,
	}
	notify.SendAsync(url, event, func(err error, dropped bool) {
		if dropped {
			metrics.WebhookSendsTotal.WithLabelValues("dropped").Inc()
			log.Info("dropping webhook notification - too many already queued", "kind", kind, "finding", name)
			return
		}
		if err != nil {
			metrics.WebhookSendsTotal.WithLabelValues("error").Inc()
			log.Error(err, "sending webhook notification", "kind", kind, "finding", name)
			return
		}
		metrics.WebhookSendsTotal.WithLabelValues("success").Inc()
	})
}

// anyPolicyAccepts reports whether at least one SignalPolicy enables sig.Provider at a
// MinSeverity the signal clears. If multiple policies in a namespace enable the same provider at
// different thresholds, the signal only needs to clear one of them - each policy is an
// independent opt-in, not a combined gate.
func anyPolicyAccepts(policies []candorv1alpha1.SignalPolicy, sig Signal) bool {
	for _, p := range policies {
		if !providerEnabled(p.Spec.Providers, sig.Provider) {
			continue
		}
		threshold := p.Spec.MinSeverity
		if threshold == "" {
			threshold = SeverityHigh // matches the CRD's +kubebuilder:default
		}
		if AtLeast(sig.Severity, threshold) {
			return true
		}
	}
	return false
}

// listRelevantPolicies returns the SignalPolicies Ingest should consider for sig: every policy in
// its namespace by default, or exactly the one named by sig.RestrictToPolicy when set - fetched
// with a single Get rather than a namespace-wide List, since the caller that set
// RestrictToPolicy (the webhook receiver) already resolved that exact object once to authenticate
// the request in the first place - no re-fetch, no TOCTOU window between the caller's
// authentication decision and this acceptance decision (see Signal.RestrictToPolicy's doc
// comment). Never falls back to the full namespace list, which would silently reintroduce the
// namespace-wide "any policy accepts" behaviour RestrictToPolicy exists specifically to avoid.
func listRelevantPolicies(ctx context.Context, c client.Client, sig Signal) ([]candorv1alpha1.SignalPolicy, error) {
	if sig.RestrictToPolicy == nil {
		return listNamespacePolicies(ctx, c, sig.Namespace)
	}
	return []candorv1alpha1.SignalPolicy{*sig.RestrictToPolicy}, nil
}

// listNamespacePolicies lists every SignalPolicy in namespace, unrestricted - the namespace-wide
// view Ingest's own comment on the resolve path requires regardless of any per-request
// RestrictToPolicy.
func listNamespacePolicies(ctx context.Context, c client.Client, namespace string) ([]candorv1alpha1.SignalPolicy, error) {
	policies := &candorv1alpha1.SignalPolicyList{}
	if err := c.List(ctx, policies, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("listing SignalPolicies in namespace %s: %w", namespace, err)
	}
	return policies.Items, nil
}

func providerEnabled(providers []string, provider string) bool {
	return slices.Contains(providers, provider)
}

// verificationMetricLabel maps a VerificationOutcome constant (PascalCase, matching Kubernetes API
// enum convention) to the snake_case label VerificationTransitionsTotal uses (matching every other
// Prometheus label in this codebase).
var verificationMetricLabel = map[string]string{
	VerificationStillPresent: "still_present",
	VerificationResolved:     "resolved",
	VerificationRecurred:     "recurred",
}

// findingName derives a stable Finding object name from the signal's source identity (not its
// content), so re-ingesting from the same source updates one object instead of creating
// duplicates as its content changes over time. This is deliberately not the content-addressed
// fingerprint from docs/design.md pillar 2 - that's Fingerprint, stored on Status (see
// fingerprint.go), and it changes when content changes precisely so it can gate enrichment and
// let a suppressed Finding resurface. Object identity and content fingerprint answer different
// questions on purpose: "which Finding is this" vs. "has this exact content been seen before."
func findingName(sig Signal) string {
	h := sha256.Sum256([]byte(sig.Provider + "/" + sig.RefKind + "/" + sig.RefName))
	return fmt.Sprintf("%s-%s", sig.Provider, hex.EncodeToString(h[:])[:12])
}
