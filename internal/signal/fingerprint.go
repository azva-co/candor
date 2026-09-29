package signal

import (
	"crypto/sha256"
	"encoding/hex"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
)

// Fingerprint returns a content-addressed hash of sig's meaningful content - resource identity,
// severity, and summary. Two signals with identical content hash identically, regardless of
// which object they came from or when. This is the load-bearing piece of docs/design.md pillar
// 2: enrichment (once wired in, slice 4) is gated on this, not on object identity or a TTL, so
// unchanged content is never re-enriched no matter how many times a reconcile loop runs against
// it. It's a plain hex SHA-256 string, not itself secret or sensitive - safe to expose in status.
func Fingerprint(sig Signal) string {
	h := sha256.New()
	for _, field := range []string{sig.Provider, sig.Namespace, sig.Kind, sig.Name, sig.Severity, sig.Summary} {
		h.Write([]byte(field))
		h.Write([]byte{0}) // separator, so ("ab","c") and ("a","bc") never collide
	}
	return hex.EncodeToString(h.Sum(nil))
}

// NeedsEnrichment reports whether f's current content has been enriched yet. True both for a
// Finding that has never been enriched (EnrichedFingerprint == "") and one whose content changed
// since it last was (EnrichedFingerprint != Fingerprint) - this second case is what pillar 3's
// "a suppressed finding resurfaces on its own when state changes" depends on: the fingerprint
// changing is what makes it look new again.
func NeedsEnrichment(f *candorv1alpha1.Finding) bool {
	return f.Status.EnrichedFingerprint != f.Status.Fingerprint
}
