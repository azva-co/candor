package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
)

func finding(namespace, name, severity, outcome string) *candorv1alpha1.Finding {
	return &candorv1alpha1.Finding{
		Name: name, Namespace: namespace,
		Spec: candorv1alpha1.FindingSpec{
			Source:   candorv1alpha1.FindingSource{Provider: "trivy", Kind: "Deployment", Name: "api", RefKind: "VulnerabilityReport", RefName: "api"},
			Severity: severity,
			Summary:  "test",
		},
		Status: candorv1alpha1.FindingStatus{VerificationOutcome: outcome},
	}
}

func TestFindingsCollector_GroupsByNamespaceSeverityOutcome(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		finding("team-a", "f1", "CRITICAL", "StillPresent"),
		finding("team-a", "f2", "CRITICAL", "StillPresent"),
		finding("team-a", "f3", "HIGH", "Resolved"),
		finding("team-b", "f4", "CRITICAL", "Recurred"),
	).Build()

	collector := &FindingsCollector{Reader: c}
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(collector); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		namespace, severity, outcome string
		want                         float64
	}{
		{"team-a", "CRITICAL", "StillPresent", 2},
		{"team-a", "HIGH", "Resolved", 1},
		{"team-b", "CRITICAL", "Recurred", 1},
	}
	for _, c := range cases {
		got := findGauge(t, registry, c.namespace, c.severity, c.outcome)
		if got != c.want {
			t.Errorf("candor_findings_current{namespace=%q,severity=%q,outcome=%q} = %v, want %v", c.namespace, c.severity, c.outcome, got, c.want)
		}
	}
}

func TestFindingsCollector_EmptyOutcome_LabeledUnverified(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		finding("team-a", "f1", "HIGH", ""),
	).Build()

	collector := &FindingsCollector{Reader: c}
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(collector); err != nil {
		t.Fatal(err)
	}

	got := findGauge(t, registry, "team-a", "HIGH", unverifiedOutcome)
	if got != 1 {
		t.Errorf("candor_findings_current{...,outcome=Unverified} = %v, want 1", got)
	}
}

func TestFindingsCollector_NoFindings_NoMetrics(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := candorv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	collector := &FindingsCollector{Reader: c}
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(collector); err != nil {
		t.Fatal(err)
	}

	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == "candor_findings_current" && len(f.GetMetric()) != 0 {
			t.Errorf("expected no candor_findings_current samples with zero Findings, got %d", len(f.GetMetric()))
		}
	}
}

// findGauge gathers registry and returns the value of the one candor_findings_current sample
// matching the given labels, failing the test if there isn't exactly one.
func findGauge(t *testing.T, registry *prometheus.Registry, namespace, severity, outcome string) float64 {
	t.Helper()
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() != "candor_findings_current" {
			continue
		}
		for _, m := range f.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["namespace"] == namespace && labels["severity"] == severity && labels["outcome"] == outcome {
				return m.GetGauge().GetValue()
			}
		}
	}
	t.Fatalf("no candor_findings_current sample found for namespace=%q severity=%q outcome=%q", namespace, severity, outcome)
	return 0
}
