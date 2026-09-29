package signal

import (
	"testing"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
)

func TestFingerprint_SameContentSameHash(t *testing.T) {
	a := testSignal(SeverityCritical)
	a.Summary = "3 critical vulns"
	b := a // identical copy

	if Fingerprint(a) != Fingerprint(b) {
		t.Error("identical Signal content produced different fingerprints")
	}
}

func TestFingerprint_ChangesWithContent(t *testing.T) {
	base := testSignal(SeverityCritical)
	base.Summary = "3 critical vulns"
	baseFP := Fingerprint(base)

	cases := map[string]Signal{
		"severity changed": withSeverity(base, SeverityHigh),
		"summary changed":  withSummary(base, "5 critical vulns"),
		"name changed":     withName(base, "other-workload"),
	}
	for name, sig := range cases {
		t.Run(name, func(t *testing.T) {
			if Fingerprint(sig) == baseFP {
				t.Errorf("%s: fingerprint unchanged, want it to differ from the base signal", name)
			}
		})
	}
}

func TestFingerprint_NoFieldConfusion(t *testing.T) {
	// "ab","c" and "a","bc" must not collide just because concatenation would produce the same
	// string - the separator byte in Fingerprint exists for exactly this.
	a := Signal{Provider: "ab", Namespace: "c", Kind: "x", Name: "y", Severity: SeverityLow, Summary: "s"}
	b := Signal{Provider: "a", Namespace: "bc", Kind: "x", Name: "y", Severity: SeverityLow, Summary: "s"}
	if Fingerprint(a) == Fingerprint(b) {
		t.Error("Fingerprint collided across a field boundary")
	}
}

const fpAbc = "abc" // arbitrary stand-in fingerprint value, not a real hash - just needs to be a value

func TestNeedsEnrichment(t *testing.T) {
	cases := []struct {
		name                  string
		fingerprint, enriched string
		want                  bool
	}{
		{"never enriched", fpAbc, "", true},
		{"up to date", fpAbc, fpAbc, false},
		{"content changed since enrichment", "def", fpAbc, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &candorv1alpha1.Finding{}
			f.Status.Fingerprint = c.fingerprint
			f.Status.EnrichedFingerprint = c.enriched
			if got := NeedsEnrichment(f); got != c.want {
				t.Errorf("NeedsEnrichment() = %v, want %v", got, c.want)
			}
		})
	}
}

func withSeverity(s Signal, severity string) Signal { s.Severity = severity; return s }
func withSummary(s Signal, summary string) Signal   { s.Summary = summary; return s }
func withName(s Signal, name string) Signal         { s.Name = name; return s }
