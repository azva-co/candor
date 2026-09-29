// Package trivy is the first signal provider: it watches Trivy Operator's VulnerabilityReport
// custom resources and translates them into signal.Signal values. It does not import Trivy
// Operator's Go module - VulnerabilityReport is read as unstructured data, matching the design
// doc's provider pattern ("consumes native Kubernetes Custom Resources") and keeping this
// provider decoupled from any particular Trivy Operator version.
//
// Schema reference: the fields read here (report.summary.*, report.artifact.*, and the
// trivy-operator.resource.* labels) are pinned against the real upstream CRD and source at
// https://github.com/aquasecurity/trivy-operator (deploy/helm/crds/aquasecurity.github.io_vulnerabilityreports.yaml
// and pkg/trivyoperator/constants.go) - not guessed. A copy of that CRD lives at
// test/crd/aquasecurity.github.io_vulnerabilityreports.yaml for envtest to validate against.
package trivy

import (
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/azva-co/candor/internal/signal"
)

// ProviderName is how this provider identifies itself in Signal.Provider and how a SignalPolicy
// enables it (SignalPolicySpec.Providers).
const ProviderName = "trivy"

// GroupVersionKind of the object this provider watches.
var GroupVersionKind = schema.GroupVersionKind{
	Group:   "aquasecurity.github.io",
	Version: "v1alpha1",
	Kind:    "VulnerabilityReport",
}

// Real, pinned label keys Trivy Operator sets on every VulnerabilityReport, linking it back to
// the workload it scanned. See pkg/trivyoperator/constants.go in aquasecurity/trivy-operator.
const (
	labelResourceKind = "trivy-operator.resource.kind"
	labelResourceName = "trivy-operator.resource.name"
)

// translate reads a VulnerabilityReport and produces a Signal, or ok=false if it isn't linked to a
// workload at all (no resource labels) - there's no resource identity to report against, so
// there's nothing translate can produce either way.
//
// A workload-linked report with zero vulnerabilities at every severity still produces a Signal
// (ok=true), with Severity left empty: signal.AtLeast never matches an unrecognised severity
// against any real threshold, so this is guaranteed to be filtered by signal.Ingest - which is
// exactly the point. Ingest's filtered path resolves any Finding that already exists for this
// source, so a previously-vulnerable workload that's now clean gets its Finding marked Resolved
// instead of left showing stale severity forever (docs/design.md pillar 4). Returning ok=false
// here instead would have skipped Ingest entirely and lost that.
func translate(u *unstructured.Unstructured) (sig signal.Signal, ok bool, err error) {
	labels := u.GetLabels()
	resourceKind := labels[labelResourceKind]
	resourceName := labels[labelResourceName]
	if resourceKind == "" || resourceName == "" {
		return signal.Signal{}, false, nil
	}

	counts, found, err := unstructured.NestedMap(u.Object, "report", "summary")
	if err != nil {
		return signal.Signal{}, false, fmt.Errorf("reading report.summary: %w", err)
	}
	if !found {
		// No report.summary at all - not the same as "confirmed zero vulnerabilities" below,
		// which needs the summary object to actually be present with all-zero counts. The real
		// upstream schema requires this field, so this is a malformed/incomplete object in
		// practice, not a clean report - nothing to translate either way.
		return signal.Signal{}, false, nil
	}

	critical := intCount(counts, "criticalCount")
	high := intCount(counts, "highCount")
	medium := intCount(counts, "mediumCount")
	low := intCount(counts, "lowCount")

	repository, _, _ := unstructured.NestedString(u.Object, "report", "artifact", "repository")
	tag, _, _ := unstructured.NestedString(u.Object, "report", "artifact", "tag")

	severity, hasVulnerabilities := highestNonZero(critical, high, medium, low)
	summary := fmt.Sprintf("%d critical, %d high, %d medium, %d low vulnerabilities in %s:%s",
		critical, high, medium, low, repository, tag)
	if !hasVulnerabilities {
		summary = fmt.Sprintf("no vulnerabilities found in %s:%s", repository, tag)
	}

	return signal.Signal{
		Provider:  ProviderName,
		Severity:  severity,
		Namespace: u.GetNamespace(),
		Kind:      resourceKind,
		Name:      resourceName,
		Summary:   summary,
		RefKind:   "VulnerabilityReport",
		RefName:   u.GetName(),
	}, true, nil
}

// intCount reads an int64 count field, tolerating the field being absent (treated as zero) since
// report.summary's own schema makes most of these fields optional-in-practice even though the
// upstream CRD marks several as required - a VulnerabilityReport with no findings at all is a
// real, valid object.
func intCount(counts map[string]any, key string) int64 {
	v, ok := counts[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case int64:
		return n
	case float64:
		return int64(n)
	default:
		return 0
	}
}

// highestNonZero returns the highest severity with a non-zero count, in CRITICAL > HIGH > MEDIUM
// > LOW order, or ok=false if all four are zero.
func highestNonZero(critical, high, medium, low int64) (severity string, ok bool) {
	switch {
	case critical > 0:
		return signal.SeverityCritical, true
	case high > 0:
		return signal.SeverityHigh, true
	case medium > 0:
		return signal.SeverityMedium, true
	case low > 0:
		return signal.SeverityLow, true
	default:
		return "", false
	}
}
