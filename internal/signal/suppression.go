package signal

import (
	"context"
	"fmt"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
)

// FindActiveSuppression returns the Suppression in namespace that currently mutes fingerprint, or
// nil if none applies. An expired Suppression (ExpiresAt in the past) is treated as inert, not a
// match - the object itself is left alone (see SuppressionReconciler's Expired condition), but it
// no longer suppresses anything.
func FindActiveSuppression(ctx context.Context, c client.Client, namespace, fingerprint string) (*candorv1alpha1.Suppression, error) {
	if fingerprint == "" {
		return nil, nil
	}

	list := &candorv1alpha1.SuppressionList{}
	if err := c.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("listing Suppressions in namespace %s: %w", namespace, err)
	}

	now := time.Now()
	for i := range list.Items {
		s := &list.Items[i]
		if s.Spec.Fingerprint != fingerprint {
			continue
		}
		if s.Spec.ExpiresAt != nil && !s.Spec.ExpiresAt.After(now) {
			continue
		}
		return s, nil
	}
	return nil, nil
}
