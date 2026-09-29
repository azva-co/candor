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
	"fmt"
	"math"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
	"github.com/azva-co/candor/internal/gitops"
	"github.com/azva-co/candor/internal/llm"
	"github.com/azva-co/candor/internal/metrics"
	"github.com/azva-co/candor/internal/signal"
)

// conditionSuppressed is the Finding status condition type set while an active Suppression
// matches its current fingerprint (see internal/signal.FindActiveSuppression).
const conditionSuppressed = "Suppressed"

// FindingReconciler reconciles a Finding object: when its content needs enrichment (see
// internal/signal.NeedsEnrichment - the gate slice 3 built for exactly this), it calls LLM.Enrich
// exactly once and records the result. When it doesn't, this is a true no-op - no LLM call, no
// write. That's the entire cost-accountability claim in one sentence: unchanged content is never
// re-enriched, no matter how many times this function runs against it.
type FindingReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// LLM enriches Findings. nil means enrichment is disabled (no API key configured) -
	// Reconcile skips enrichment entirely rather than erroring, the same "not configured, so
	// skip" stance internal/provider takes for a missing CRD. A cluster running Candor for
	// deterministic findings only, with no LLM cost at all, is a fully supported configuration,
	// not a degraded one.
	LLM llm.Client

	// GitOps opens the pull request ProposePullRequest carries. nil means that action is never
	// attempted regardless of what a Hypothesis recommends or what SignalPolicy.Spec.GitOpsRepo
	// says - the same "not configured, so skip" stance LLM being nil already takes for enrichment.
	GitOps gitops.Opener

	// Recorder emits Kubernetes Events on state transitions worth an operator's attention (budget
	// exhaustion, a pull request opened or its own budget exhausted). Required if LLM is set - see
	// SetupWithManager.
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=candor.dev,resources=findings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=candor.dev,resources=findings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=candor.dev,resources=findings/finalizers,verbs=update
// +kubebuilder:rbac:groups=candor.dev,resources=signalpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=candor.dev,resources=signalpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=candor.dev,resources=suppressions,verbs=get;list;watch
// +kubebuilder:rbac:groups=candor.dev,resources=operatingpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=candor.dev,resources=operatingpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
//
// Deliberately no cluster-wide `secrets` RBAC marker here. A ClusterRole granting `get` on
// Secrets at cluster scope is equivalent to cluster-admin in most clusters (Trivy KSV-0041: any
// other Secret in the cluster becomes readable, not just the one this controller actually needs) -
// exactly the kind of unbounded blast radius docs/design.md pillar 1 rules out. Reading
// SignalPolicy.Spec.GitOpsRepo.SecretRef is real least-privilege-by-default: the namespace that
// sets GitOpsRepo grants the controller's ServiceAccount a namespaced Role naming that one Secret,
// the same opt-in-per-namespace posture SignalPolicy itself already requires (see that type's own
// doc comment). Missing RBAC surfaces as a normal Forbidden error on the Get call below, which
// requeues and logs - the same "fail loud, not silent" posture as every other error path here.

func (r *FindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	finding := &candorv1alpha1.Finding{}
	if err := r.Get(ctx, req.NamespacedName, finding); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Suppression is checked regardless of whether an LLM is configured - it's about noise, not
	// LLM spend, so it applies even to a deterministic-findings-only cluster. Checked before
	// anything else so a suppressed Finding never reaches the LLM gate below it.
	suppression, err := signal.FindActiveSuppression(ctx, r.Client, finding.Namespace, finding.Status.Fingerprint)
	if err != nil {
		return ctrl.Result{}, err
	}

	if suppression != nil {
		meta.SetStatusCondition(&finding.Status.Conditions, metav1.Condition{
			Type:               conditionSuppressed,
			Status:             metav1.ConditionTrue,
			Reason:             "Suppressed",
			Message:            suppression.Spec.Reason,
			ObservedGeneration: finding.Generation,
		})
		if err := r.Status().Update(ctx, finding); err != nil {
			return ctrl.Result{}, err
		}
		metrics.EnrichmentSkippedTotal.WithLabelValues("suppressed").Inc()

		result := ctrl.Result{}
		if suppression.Spec.ExpiresAt != nil {
			// Requeue exactly when the Suppression lapses, so the Finding gets re-evaluated (and
			// its condition cleared) without waiting on some other event to touch it first.
			result.RequeueAfter = time.Until(suppression.Spec.ExpiresAt.Time)
		}
		return result, nil
	}

	if meta.FindStatusCondition(finding.Status.Conditions, conditionSuppressed) != nil {
		meta.RemoveStatusCondition(&finding.Status.Conditions, conditionSuppressed)
		if err := r.Status().Update(ctx, finding); err != nil {
			return ctrl.Result{}, err
		}
	}

	if r.LLM == nil {
		metrics.EnrichmentSkippedTotal.WithLabelValues("no_llm_configured").Inc()
		return ctrl.Result{}, nil
	}

	// The budget lives on whichever SignalPolicy governs this Finding's provider in its
	// namespace - same lookup Ingest uses to decide whether to accept a signal at all. If the
	// policy was deleted after ingest (an edge case, not the common path), there's nothing to
	// enforce against - treated as unlimited, same as a policy with no Budget configured. Looked
	// up unconditionally (not only when enrichment is needed): tryProposePullRequest below also
	// needs it, on reconciles where enrichment already happened in an earlier pass (a periodic
	// resync of unchanged content, or retrying a pull request attempt that previously errored) - a
	// namespace-scoped List is negligible next to what this function guards against actually
	// spending (an LLM call, a pull request).
	policy, err := signal.FindPolicy(ctx, r.Client, finding.Namespace, finding.Spec.Source.Provider)
	if err != nil {
		return ctrl.Result{}, err
	}

	if signal.NeedsEnrichment(finding) {
		if policy != nil {
			allowed, err := signal.CheckBudget(ctx, r.Client, policy)
			if err != nil {
				return ctrl.Result{}, err
			}
			if policy.Spec.Budget != nil {
				metrics.BudgetCallsLimit.WithLabelValues(policy.Namespace, policy.Name).Set(float64(policy.Spec.Budget.MaxCalls))
				metrics.BudgetCallsUsed.WithLabelValues(policy.Namespace, policy.Name).Set(float64(policy.Status.BudgetCallsUsed))
			}
			if !allowed {
				metrics.EnrichmentSkippedTotal.WithLabelValues("budget_exhausted").Inc()
				// Emitted every time budget blocks a call, not just on the first transition - the
				// Kubernetes Events API already coalesces repeated identical (object, reason)
				// events into one Event with an incrementing count, so this doesn't spam.
				r.Recorder.Eventf(policy, corev1.EventTypeWarning, "BudgetExhausted",
					"enrichment for %s/%s skipped - budget exhausted (%d/%d calls this window)",
					finding.Namespace, finding.Name, policy.Status.BudgetCallsUsed, policy.Spec.Budget.MaxCalls)
				return ctrl.Result{}, nil
			}
		}

		resp, err := r.LLM.Enrich(ctx, llm.Request{
			Provider: finding.Spec.Source.Provider,
			Severity: finding.Spec.Severity,
			Summary:  finding.Spec.Summary,
			Kind:     finding.Spec.Source.Kind,
			Name:     finding.Spec.Source.Name,
		})
		if err != nil {
			metrics.LLMCallsTotal.WithLabelValues("error").Inc()
			// Returned as-is: controller-runtime requeues failed reconciles with its own
			// exponential backoff, so a transient API error (rate limit, timeout) retries on its
			// own without this needing to hand-roll that.
			log.Error(err, "LLM enrichment failed")
			return ctrl.Result{}, err
		}
		metrics.LLMCallsTotal.WithLabelValues("success").Inc()

		finding.Status.Hypotheses = toHypotheses(resp.Hypotheses)
		finding.Status.EnrichedFingerprint = finding.Status.Fingerprint
		if err := r.Status().Update(ctx, finding); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		metrics.EnrichmentSkippedTotal.WithLabelValues("not_needed").Inc()
	}

	if err := r.tryProposePullRequest(ctx, finding, policy); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// tryProposePullRequest attempts ProposePullRequest for finding's top hypothesis. It is a no-op -
// silently degrading to Notify, which internal/signal.Ingest already queued for this Finding onto
// notify's shared async pool (best-effort - it may still be in flight, or dropped if that pool was
// saturated, not a guaranteed-delivered fact) - whenever any precondition isn't met: GitOps isn't
// wired up, policy has no GitOpsRepo, the top
// hypothesis didn't recommend it, this exact fingerprint was already attempted, the OperatingPolicy
// panic switch is in Audit mode (docs/design.md:189, checked first and before either budget is
// touched, so it's a genuine full stop), no concrete fix can be mechanically derived
// (internal/gitops.ComputeFix), the per-namespace pull request budget is exhausted, or the
// cluster-wide OperatingPolicy rate limit is exhausted (checked in addition to and after the
// per-namespace one).
//
// Two distinct kinds of "didn't happen" are deliberately handled differently, mirroring how
// NeedsEnrichment/EnrichedFingerprint already treat the LLM path:
//   - "no mechanical fix exists for this content" is a deterministic property of the Finding's
//     current fingerprint - it marks ProposedPullRequestFingerprint so it isn't recomputed on
//     every resync, the same "no repeat work for unchanged content" rule EnrichedFingerprint
//     already enforces for LLM calls.
//   - Pull request budget exhaustion and a real error opening the pull request are both
//     transient, policy-level or infrastructure conditions unrelated to this Finding's content -
//     neither marks the fingerprint, so a later reconcile (a resync, or controller-runtime's own
//     backoff after a returned error) gets a genuine second chance once the condition clears.
//
// Only a real error opening the pull request (or reading its prerequisites) is returned from this
// function, so the reconcile retries with controller-runtime's own backoff - the same posture as
// the LLM.Enrich call above.
func (r *FindingReconciler) tryProposePullRequest(ctx context.Context, finding *candorv1alpha1.Finding, policy *candorv1alpha1.SignalPolicy) error {
	log := logf.FromContext(ctx)

	if r.GitOps == nil || policy == nil || policy.Spec.GitOpsRepo == nil {
		return nil
	}
	if len(finding.Status.Hypotheses) == 0 || finding.Status.Hypotheses[0].RecommendedAction != candorv1alpha1.ActionProposePullRequest {
		return nil
	}
	if finding.Status.ProposedPullRequestFingerprint == finding.Status.Fingerprint {
		return nil
	}

	// Checked before anything else, including before computing a fix or touching either budget:
	// the panic switch (docs/design.md:189) is meant to be a genuine, immediate full stop, not
	// "still counted against a namespace's budget but not executed". A namespace's own allowance
	// is untouched while Audit mode is active.
	operatingPolicy, err := signal.FindOperatingPolicy(ctx, r.Client)
	if err != nil {
		return fmt.Errorf("finding OperatingPolicy: %w", err)
	}
	if signal.InAuditMode(operatingPolicy) {
		metrics.PullRequestsTotal.WithLabelValues("audit_mode").Inc()
		r.Recorder.Eventf(operatingPolicy, corev1.EventTypeWarning, "AuditModeActive",
			"ProposePullRequest for %s/%s skipped - OperatingPolicy is in Audit mode", finding.Namespace, finding.Name)
		return nil
	}

	fix, ok, err := gitops.ComputeFix(ctx, r.Client, finding)
	if err != nil {
		return fmt.Errorf("computing fix for Finding %s/%s: %w", finding.Namespace, finding.Name, err)
	}
	if !ok {
		metrics.PullRequestsTotal.WithLabelValues("no_mechanical_fix").Inc()
		return r.markPullRequestFingerprintAttempted(ctx, finding)
	}

	// Read and validate the Secret before either budget below is touched. Both budgets persist
	// their spend the moment they say "allowed", not on actual success - a misconfigured Secret
	// (missing, wrong key) fails identically on every retry, and reordering this ahead of them
	// means that failure keeps surfacing as a visible error instead of silently exhausting a
	// namespace's or the cluster's entire pull request allowance (as low as 1/24h) on an attempt
	// that could never have succeeded regardless of budget.
	secretKey := client.ObjectKey{Namespace: policy.Namespace, Name: policy.Spec.GitOpsRepo.SecretRef.Name}
	tokenBytes, err := signal.ResolveSecretKey(ctx, r.Client, secretKey, "token")
	if err != nil {
		return fmt.Errorf("resolving GitOpsRepo secret: %w", err)
	}
	token := string(tokenBytes)

	allowed, err := signal.CheckPullRequestBudget(ctx, r.Client, policy)
	if err != nil {
		return fmt.Errorf("checking pull request budget for SignalPolicy %s/%s: %w", policy.Namespace, policy.Name, err)
	}
	if !allowed {
		metrics.PullRequestsTotal.WithLabelValues("budget_exhausted").Inc()
		r.Recorder.Eventf(policy, corev1.EventTypeWarning, "PullRequestBudgetExhausted",
			"ProposePullRequest for %s/%s skipped - pull request budget exhausted (%d/%d this window)",
			finding.Namespace, finding.Name, policy.Status.PullRequestsOpened, signal.MaxPullRequests(policy))
		return nil
	}

	// Checked in addition to, and after, the per-namespace budget above: a namespace can sit
	// comfortably under its own cap while the cluster-wide ceiling is exhausted by everyone else
	// combined (docs/design.md:189's "one noisy provider cannot exhaust the whole cluster's
	// allowance"). Both must allow before a pull request opens.
	globalAllowed, err := signal.CheckGlobalPullRequestBudget(ctx, r.Client, operatingPolicy)
	if err != nil {
		return fmt.Errorf("checking global pull request budget: %w", err)
	}
	if !globalAllowed {
		metrics.PullRequestsTotal.WithLabelValues("global_budget_exhausted").Inc()
		r.Recorder.Eventf(operatingPolicy, corev1.EventTypeWarning, "GlobalPullRequestBudgetExhausted",
			"ProposePullRequest for %s/%s skipped - cluster-wide pull request budget exhausted",
			finding.Namespace, finding.Name)
		return nil
	}

	prURL, err := r.GitOps.Open(ctx, token, policy.Spec.GitOpsRepo, fix, finding)
	if err != nil {
		metrics.PullRequestsTotal.WithLabelValues("error").Inc()
		log.Error(err, "opening pull request", "finding", finding.Name)
		return fmt.Errorf("opening pull request for Finding %s/%s: %w", finding.Namespace, finding.Name, err)
	}
	metrics.PullRequestsTotal.WithLabelValues("success").Inc()

	finding.Status.ProposedPullRequestURL = prURL
	if err := r.markPullRequestFingerprintAttempted(ctx, finding); err != nil {
		return err
	}
	r.Recorder.Eventf(finding, corev1.EventTypeNormal, "PullRequestProposed", "opened %s", prURL)

	return nil
}

// markPullRequestFingerprintAttempted records that ProposePullRequest has been decided (one way or
// another, not necessarily successfully) for finding's current fingerprint. Also persists
// ProposedPullRequestURL when the caller already set it in memory (the success path) - a single
// Status().Update() covers both fields.
func (r *FindingReconciler) markPullRequestFingerprintAttempted(ctx context.Context, finding *candorv1alpha1.Finding) error {
	finding.Status.ProposedPullRequestFingerprint = finding.Status.Fingerprint
	if err := r.Status().Update(ctx, finding); err != nil {
		return fmt.Errorf("recording pull request attempt on Finding %s/%s: %w", finding.Namespace, finding.Name, err)
	}
	return nil
}

// toHypotheses converts llm.Hypothesis (Confidence as a 0.0-1.0 float64, fine for an in-process
// API response type) to the CRD's Hypothesis (Confidence as a 0-100 int32 - Kubernetes API
// convention discourages floats in CRD schemas; see the field's doc comment).
func toHypotheses(in []llm.Hypothesis) []candorv1alpha1.Hypothesis {
	out := make([]candorv1alpha1.Hypothesis, 0, len(in))
	for _, h := range in {
		out = append(out, candorv1alpha1.Hypothesis{
			Cause:             h.Cause,
			Confidence:        int32(math.Round(h.Confidence * 100)),
			Rationale:         h.Rationale,
			RecommendedAction: sanitizeRecommendedAction(h.RecommendedAction),
		})
	}
	return out
}

// sanitizeRecommendedAction validates an LLM's recommended action against Candor's fixed catalog,
// independent of which backend produced it. This is real defense in depth, not redundant with the
// CRD's own `+kubebuilder:validation:Enum` on Hypothesis.RecommendedAction: without this, an
// out-of-catalog value would make the API server reject the *whole* status update, not just drop
// the bad field, blocking every valid hypothesis alongside it and causing an endless reconcile
// retry against a backend that keeps producing the same bad value. Anthropic's own structured
// outputs make this unreachable in practice today, but a less-constrained backend (docs/design.md's
// deferred fine-tuned-model note: "the independent validation... stays necessary regardless - this
// was one model, one test, defense in depth, not proof it holds for every model") could reach it.
func sanitizeRecommendedAction(action string) string {
	switch action {
	case "", candorv1alpha1.ActionNotify, candorv1alpha1.ActionProposePullRequest:
		return action
	default:
		return ""
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *FindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Recorder == nil {
		// GetEventRecorderFor is deprecated in favour of GetEventRecorder (the events.k8s.io/v1
		// API), but controller-runtime's own internal.go still calls it internally with the same
		// suppression - the old client-go record.EventRecorder is what every reference
		// controller in the ecosystem still uses, and migrating buys nothing right now against a
		// "not yet removed" warning. Worth revisiting if it's ever actually scheduled for
		// removal.
		r.Recorder = mgr.GetEventRecorderFor("candor") //nolint:staticcheck
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&candorv1alpha1.Finding{}).
		Watches(&candorv1alpha1.Suppression{}, handler.EnqueueRequestsFromMapFunc(r.findingsForSuppression)).
		Named("finding").
		Complete(r)
}

// findingsForSuppression maps a Suppression event (create/update/delete) to the Findings in its
// namespace whose current fingerprint it mutes - the watch that makes suppression apply and lift
// promptly, rather than only on the next unrelated Finding event.
func (r *FindingReconciler) findingsForSuppression(ctx context.Context, obj client.Object) []reconcile.Request {
	suppression, ok := obj.(*candorv1alpha1.Suppression)
	if !ok {
		return nil
	}

	findings := &candorv1alpha1.FindingList{}
	if err := r.List(ctx, findings, client.InNamespace(suppression.Namespace)); err != nil {
		logf.FromContext(ctx).Error(err, "listing Findings for Suppression watch", "suppression", suppression.Name)
		return nil
	}

	var requests []reconcile.Request
	for i := range findings.Items {
		f := &findings.Items[i]
		if f.Status.Fingerprint == suppression.Spec.Fingerprint {
			requests = append(requests, reconcile.Request{
				Namespace: f.Namespace, Name: f.Name,
			})
		}
	}
	return requests
}
