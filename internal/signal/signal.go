// Package signal defines the common representation every provider translates its native signal
// format into, and the single choke point (Ingest) that turns a Signal into a Finding. This is
// the seam the design doc's "provider pattern" depends on: a provider's only job is producing a
// Signal; everything after that - policy filtering, fingerprinting (later), LLM enrichment
// (later), budget accounting (later) - happens once, here, not once per provider.
package signal

import candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"

// Severity levels, ordered low to high. Matches the enum on SignalPolicy.Spec.MinSeverity and
// Finding.Spec.Severity.
const (
	SeverityLow      = "LOW"
	SeverityMedium   = "MEDIUM"
	SeverityHigh     = "HIGH"
	SeverityCritical = "CRITICAL"
)

// severityRank orders severities for threshold comparisons. Not exported - callers compare via
// AtLeast, so the ranking scheme can change without becoming part of the package's API.
var severityRank = map[string]int{
	SeverityLow:      0,
	SeverityMedium:   1,
	SeverityHigh:     2,
	SeverityCritical: 3,
}

// Verification outcomes, written to Finding.Status.VerificationOutcome by Ingest. See that field's
// doc comment for what each one means and why there are three, not the design doc's full four.
const (
	VerificationStillPresent = "StillPresent"
	VerificationResolved     = "Resolved"
	VerificationRecurred     = "Recurred"
)

// AtLeast reports whether severity a is at least as severe as severity b. An unrecognised
// severity ranks below every known one, so it never clears a real threshold.
func AtLeast(a, b string) bool {
	ra, ok := severityRank[a]
	if !ok {
		return false
	}
	rb, ok := severityRank[b]
	if !ok {
		return false
	}
	return ra >= rb
}

// Signal is one provider's deterministic reading of one piece of evidence about one Kubernetes
// resource. Never carries an LLM opinion - Summary is generated from the signal's own data, not
// inferred. LLM-derived hypotheses attach to the resulting Finding in a later slice, kept
// separate so it's always possible to tell which parts of a Finding are fact and which are
// interpretation.
type Signal struct {
	// Provider identifies which provider produced this signal, e.g. "trivy". Free-form, not a
	// closed enum - see SignalPolicy.Spec.Providers for why.
	Provider string

	// Severity of the underlying evidence. One of the Severity* constants.
	Severity string

	// Namespace, Kind, Name identify the Kubernetes resource this signal is about - the workload,
	// not the signal source object itself.
	Namespace string
	Kind      string
	Name      string

	// Summary is a short, deterministic, human-readable description.
	Summary string

	// RefKind, RefName identify the object this signal was read from (e.g. a Trivy
	// VulnerabilityReport), for traceability back to raw evidence. Same namespace as the signal.
	RefKind string
	RefName string

	// RestrictToPolicy, if set, limits Ingest's initial acceptance check to exactly this
	// SignalPolicy, instead of the default namespace-wide "any policy accepts" semantics every
	// CRD-backed provider relies on. Set by providers whose signal is authenticated against one
	// specific policy's own credentials (the webhook receiver, verified against that policy's
	// SecretRef) - without this, a signal authenticated against one policy's secret could be
	// accepted by a different, laxer policy in the same namespace, defeating the point of
	// per-policy authentication.
	//
	// The caller's already-fetched object, not just a name: Ingest uses it directly rather than
	// re-fetching, both to avoid a redundant apiserver call (the caller already fetched it once
	// to authenticate the request) and to avoid a TOCTOU window between the caller's
	// authentication decision and Ingest's acceptance decision - a watch update landing between
	// a re-fetch and the original Get could otherwise authenticate against one policy state and
	// accept against a different one.
	//
	// Deciding whether to RESOLVE an existing Finding never uses this restriction, even when set
	// - see Ingest's own comment on that path for why: Finding identity has no policy component,
	// so a different, still-active sibling policy's ongoing interest in it must not be
	// overridden by one request's narrower authorization scope. Nil for CRD-based providers
	// (Trivy), which have no such per-object identity to restrict to.
	RestrictToPolicy *candorv1alpha1.SignalPolicy
}
