package trivy

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/azva-co/candor/internal/signal"
)

const (
	fieldCritical = "criticalCount"
	fieldHigh     = "highCount"
	fieldMedium   = "mediumCount"
	fieldLow      = "lowCount"

	testKind = "Deployment"
	testName = "api"
)

var testLabels = map[string]string{labelResourceKind: testKind, labelResourceName: testName}

func vulnReport(labels map[string]string, summary map[string]any, repository, tag string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(GroupVersionKind)
	u.SetName("api-abc123")
	u.SetNamespace("team-a")
	u.SetLabels(labels)
	_ = unstructured.SetNestedMap(u.Object, summary, "report", "summary")
	if repository != "" {
		_ = unstructured.SetNestedField(u.Object, repository, "report", "artifact", "repository")
	}
	if tag != "" {
		_ = unstructured.SetNestedField(u.Object, tag, "report", "artifact", "tag")
	}
	return u
}

func TestTranslate_NoResourceLabels_NotOK(t *testing.T) {
	u := vulnReport(nil, map[string]any{fieldCritical: int64(3)}, "repo", "v1")
	_, ok, err := translate(u)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected ok=false for a report with no trivy-operator.resource.* labels")
	}
}

// TestTranslate_ZeroVulnerabilities_ProducesFilterableSignal proves the mechanism
// internal/signal.Ingest's resolution path (ResultResolved) depends on: a workload-linked report
// with zero vulnerabilities must still produce a Signal, not be silently dropped, so a previously
// -vulnerable workload that's now clean can be recognised and its Finding resolved rather than
// left showing stale severity.
func TestTranslate_ZeroVulnerabilities_ProducesFilterableSignal(t *testing.T) {
	u := vulnReport(testLabels, map[string]any{
		fieldCritical: int64(0), fieldHigh: int64(0), fieldMedium: int64(0), fieldLow: int64(0),
	}, "repo", "v1")
	sig, ok, err := translate(u)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected ok=true even when every severity count is zero - see the function's doc comment")
	}
	if sig.Severity != "" {
		t.Errorf("Severity = %q, want empty (never clears any real SignalPolicy threshold, by design)", sig.Severity)
	}
	if sig.Summary != "no vulnerabilities found in repo:v1" {
		t.Errorf("Summary = %q, want a clean-report message", sig.Summary)
	}
}

func TestTranslate_NoSummaryField_NotOK(t *testing.T) {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(GroupVersionKind)
	u.SetName("api-abc123")
	u.SetNamespace("team-a")
	u.SetLabels(testLabels)
	// No report.summary set at all - a malformed/incomplete object, distinct from a real report
	// confirming zero vulnerabilities.

	_, ok, err := translate(u)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected ok=false when report.summary is missing entirely")
	}
}

func TestTranslate_PicksHighestNonZeroSeverity(t *testing.T) {
	cases := []struct {
		name    string
		summary map[string]any
		want    string
	}{
		{"critical wins over high", map[string]any{fieldCritical: int64(1), fieldHigh: int64(5)}, signal.SeverityCritical},
		{"high, no critical", map[string]any{fieldCritical: int64(0), fieldHigh: int64(2)}, signal.SeverityHigh},
		{"medium only", map[string]any{fieldMedium: int64(1)}, signal.SeverityMedium},
		{"low only", map[string]any{fieldLow: int64(1)}, signal.SeverityLow},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u := vulnReport(testLabels, c.summary, "ghcr.io/foo/bar", "v1.2.3")
			sig, ok, err := translate(u)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatal("expected ok=true")
			}
			if sig.Severity != c.want {
				t.Errorf("Severity = %q, want %q", sig.Severity, c.want)
			}
		})
	}
}

func TestTranslate_PopulatesSignal(t *testing.T) {
	summary := map[string]any{fieldCritical: int64(3), fieldHigh: int64(5), fieldMedium: int64(2), fieldLow: int64(1)}
	u := vulnReport(testLabels, summary, "ghcr.io/foo/bar", "v1.2.3")

	sig, ok, err := translate(u)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected ok=true")
	}

	want := signal.Signal{
		Provider:  ProviderName,
		Severity:  signal.SeverityCritical,
		Namespace: "team-a",
		Kind:      testKind,
		Name:      testName,
		Summary:   "3 critical, 5 high, 2 medium, 1 low vulnerabilities in ghcr.io/foo/bar:v1.2.3",
		RefKind:   "VulnerabilityReport",
		RefName:   "api-abc123",
	}
	if sig != want {
		t.Errorf("translate() = %+v, want %+v", sig, want)
	}
}

func TestTranslate_FloatCounts(t *testing.T) {
	// json.Unmarshal into map[string]any produces float64 for numbers - real unstructured
	// decode of a fetched object will hit this path, not int64. Both must work.
	u := vulnReport(testLabels, map[string]any{fieldCritical: float64(2)}, "repo", "v1")

	sig, ok, err := translate(u)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || sig.Severity != signal.SeverityCritical {
		t.Errorf("translate() = %+v, ok=%v, want CRITICAL severity", sig, ok)
	}
}
