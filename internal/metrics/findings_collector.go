package metrics

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/client"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
)

// findingsCurrentDesc describes candor_findings_current, the metric behind the dashboard's
// landing status tiles (docs/design.md interaction surfaces: "the dashboard is the proof
// surface"). Every other metric in this package is a transition counter (how many times
// something changed) or self-observability (LLM calls, budget) - neither answers the question a
// DevSecOps operator actually opens the dashboard for first: how many findings are open, right
// now, at each severity. A counter can't answer that correctly (verification transitions don't
// net out to a current count), so this is a live gauge instead, computed fresh on every scrape.
var findingsCurrentDesc = prometheus.NewDesc(
	"candor_findings_current",
	"Current number of Findings, by namespace, severity, and verification outcome.",
	[]string{labelNamespace, "severity", "outcome"}, nil,
)

// unverifiedOutcome labels a Finding that hasn't been through Ingest's verification-outcome
// write yet (VerificationOutcome == "") - possible only in the brief window between a Finding's
// creation and its first status write. Kept distinct from the real outcomes rather than silently
// dropped, so a scrape during that window doesn't undercount.
const unverifiedOutcome = "Unverified"

// FindingsCollector is a Prometheus collector (not a package-level metric var like the rest of
// this package) because "current count grouped by attributes" has to be computed from source
// truth at scrape time - the same reasoning kube-state-metrics is built on. Registered directly
// with controller-runtime's metrics.Registry in cmd/main.go, using the manager's own cached
// client - no extra List calls beyond what the cache already maintains from the controllers'
// own watches.
type FindingsCollector struct {
	Reader client.Reader
}

func (c *FindingsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- findingsCurrentDesc
}

// Collect lists every Finding and emits one gauge sample per distinct (namespace, severity,
// outcome) combination actually present - not one per possible combination, so a combination
// with zero Findings simply doesn't appear, rather than reporting a bare 0 (Prometheus and
// Grafana's `sum(...)  or vector(0)` pattern handle an absent series the same way as an explicit
// zero for this dashboard's purposes).
//
// Best-effort on a List failure: an error here means this scrape has no data for this metric,
// not a crash - the next scrape interval tries again, matching every other best-effort pattern
// in this codebase (see internal/notify.Send's callers).
func (c *FindingsCollector) Collect(ch chan<- prometheus.Metric) {
	var list candorv1alpha1.FindingList
	if err := c.Reader.List(context.Background(), &list); err != nil {
		return
	}

	type key struct{ namespace, severity, outcome string }
	counts := make(map[key]int, len(list.Items))
	for _, f := range list.Items {
		outcome := f.Status.VerificationOutcome
		if outcome == "" {
			outcome = unverifiedOutcome
		}
		counts[key{f.Namespace, f.Spec.Severity, outcome}]++
	}

	for k, v := range counts {
		ch <- prometheus.MustNewConstMetric(findingsCurrentDesc, prometheus.GaugeValue, float64(v), k.namespace, k.severity, k.outcome)
	}
}
