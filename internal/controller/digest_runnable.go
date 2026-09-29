/*
Copyright 2026 Albert Asawaroengchai.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
	"github.com/azva-co/candor/internal/metrics"
	"github.com/azva-co/candor/internal/notify"
	"github.com/azva-co/candor/internal/signal"
)

// DigestRunnable sends the periodic per-namespace summary docs/design.md calls for ("findings
// raised/resolved/recurred, accuracy, spend vs budget... delivered over the webhook sink") - the
// artifact the "AIOps: Prove It!" critique asks for. It runs on a plain ticker as a manager
// Runnable (mgr.Add, see cmd/main.go), not a CRD-triggered reconciler - there's no event to react
// to for "time has passed."
type DigestRunnable struct {
	client.Client
	// Interval between digests. Zero or negative disables the digest entirely - Start returns
	// immediately without ever ticking.
	Interval time.Duration
}

// +kubebuilder:rbac:groups=candor.dev,resources=signalpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=candor.dev,resources=findings,verbs=get;list;watch

var _ manager.Runnable = &DigestRunnable{}

func (d *DigestRunnable) Start(ctx context.Context) error {
	if d.Interval <= 0 {
		return nil
	}

	ticker := time.NewTicker(d.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			d.sendDigests(ctx)
		}
	}
}

// sendDigests lists every SignalPolicy across the cluster and, for each one with a Webhook
// configured, sends a Digest covering its own namespace's Findings. Two policies in the same
// namespace each configuring a Webhook get two digests (about the same namespace) rather than
// one deduplicated send - a deliberate simplification, since each policy's webhook is a distinct
// opt-in a different team may have configured for their own destination.
func (d *DigestRunnable) sendDigests(ctx context.Context) {
	log := logf.FromContext(ctx)

	policies := &candorv1alpha1.SignalPolicyList{}
	if err := d.List(ctx, policies); err != nil {
		log.Error(err, "listing SignalPolicies for digest")
		return
	}

	for i := range policies.Items {
		p := &policies.Items[i]
		if p.Spec.Webhook == nil {
			continue
		}

		findings := &candorv1alpha1.FindingList{}
		if err := d.List(ctx, findings, client.InNamespace(p.Namespace)); err != nil {
			log.Error(err, "listing Findings for digest", "namespace", p.Namespace)
			continue
		}

		digest := buildDigest(p.Namespace, d.Interval, findings.Items)
		namespace, policyName := p.Namespace, p.Name
		// Queued, not sent inline: a slow or unreachable webhook for one policy must not delay
		// every other policy's digest in this same tick, nor the ticker's own next fire (Start's
		// select loop calls sendDigests synchronously) - the same reasoning internal/signal.Ingest's
		// own notifyEvent documents for issue #63, sharing the same bounded worker pool.
		notify.SendAsync(p.Spec.Webhook.URL, digest, func(err error, dropped bool) {
			if dropped {
				metrics.WebhookSendsTotal.WithLabelValues("dropped").Inc()
				log.Info("dropping digest - too many notifications already queued", "namespace", namespace, "signalpolicy", policyName)
				return
			}
			if err != nil {
				metrics.WebhookSendsTotal.WithLabelValues("error").Inc()
				log.Error(err, "sending digest", "namespace", namespace, "signalpolicy", policyName)
				return
			}
			metrics.WebhookSendsTotal.WithLabelValues("success").Inc()
		})
	}
}

func buildDigest(namespace string, interval time.Duration, findings []candorv1alpha1.Finding) notify.Digest {
	digest := notify.Digest{
		Kind: notify.KindDigest, Namespace: namespace, WindowSeconds: int64(interval.Seconds()),
		BySeverity: map[string]int{},
	}
	for _, f := range findings {
		switch f.Status.VerificationOutcome {
		case signal.VerificationResolved:
			digest.Resolved++
		case signal.VerificationRecurred:
			digest.Recurred++
		default:
			digest.StillPresent++
		}
		if f.Status.VerificationOutcome != signal.VerificationResolved {
			digest.BySeverity[f.Spec.Severity]++
		}
	}
	return digest
}
