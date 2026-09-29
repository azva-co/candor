package provider

import (
	"testing"

	"github.com/azva-co/candor/internal/provider/trivy"
	"github.com/azva-co/candor/internal/provider/webhook"
)

// Known can't reference trivy.ProviderName directly (see the comment in provider.go - it would
// cycle with trivy's own tests), so this catches the two ever drifting apart by hand.
func TestKnown_MatchesTrivyProviderName(t *testing.T) {
	if !IsKnown(trivy.ProviderName) {
		t.Errorf("Known = %v does not contain trivy.ProviderName (%q) - these must be kept in sync by hand, see provider.go", Known, trivy.ProviderName)
	}
}

// Same reasoning as TestKnown_MatchesTrivyProviderName, for the webhook provider.
func TestKnown_MatchesWebhookProviderName(t *testing.T) {
	if !IsKnown(webhook.ProviderName) {
		t.Errorf("Known = %v does not contain webhook.ProviderName (%q) - these must be kept in sync by hand, see provider.go", Known, webhook.ProviderName)
	}
}
