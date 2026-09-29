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
	"strings"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
	"github.com/azva-co/candor/internal/provider"
	"github.com/azva-co/candor/internal/provider/webhook"
)

// SignalPolicyReconciler reconciles a SignalPolicy object
type SignalPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=candor.dev,resources=signalpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=candor.dev,resources=signalpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=candor.dev,resources=signalpolicies/finalizers,verbs=update

// Reconcile validates the SignalPolicy and reports whether it's actually doing anything: a
// policy naming an unrecognised provider is accepted by the API (Providers isn't a closed CRD
// enum - see SignalPolicySpec) but would otherwise silently match nothing, which is exactly the
// kind of quiet failure this project exists to avoid. There's no other state to reconcile yet -
// SignalPolicy is read by providers at signal-ingest time (see internal/signal.Ingest), not
// acted on here.
func (r *SignalPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	policy := &candorv1alpha1.SignalPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	var unknown []string
	webhookEnabled := false
	for _, p := range policy.Spec.Providers {
		if !provider.IsKnown(p) {
			unknown = append(unknown, p)
		}
		if p == webhook.ProviderName {
			webhookEnabled = true
		}
	}

	// Every applicable problem is collected, not just the first one found - a policy can be wrong
	// in more than one way at once (an unknown provider *and* a webhook misconfiguration), and a
	// switch that stops at the first case would silently hide the second until the first is fixed
	// and the policy is reconciled again, which is exactly the "quiet failure" this condition
	// exists to surface (see this function's own doc comment). One slice of paired values, not two
	// parallel slices appended independently - a future check that appends to only one of a pair
	// of parallel slices would panic or silently mispair a reason with the wrong message, and
	// nothing would catch it until it happened.
	type problem struct{ reason, message string }
	var problems []problem
	if len(unknown) > 0 {
		problems = append(problems, problem{
			reason: "UnknownProvider",
			message: fmt.Sprintf("not recognised, so this policy has no effect for: %s (known providers: %s)",
				strings.Join(unknown, ", "), strings.Join(provider.Known, ", ")),
		})
	}
	if webhookEnabled && policy.Spec.WebhookReceiver == nil {
		// The receiver fails closed identically for this case and for a nonexistent policy
		// (internal/provider/webhook, enumeration-avoidance) - Ready must say so plainly here,
		// since that response gives the operator no way to tell the two apart from the outside.
		problems = append(problems, problem{
			reason: "WebhookReceiverNotConfigured",
			message: fmt.Sprintf("%q is listed in providers but spec.webhookReceiver is not set - "+
				"every request to this policy's receiver endpoint is rejected until it is", webhook.ProviderName),
		})
	}
	if !webhookEnabled && policy.Spec.WebhookReceiver != nil {
		// The opposite misconfiguration, same failure class: the receiver only checks
		// WebhookReceiver != nil (internal/provider/webhook/receiver.go), so it authenticates the
		// request successfully and calls Ingest - which then filters every one of them, silently,
		// because "webhook" was never added to providers. Fully-authenticated traffic gets dropped
		// with nothing in the response or this condition to say why, unless this case says so.
		problems = append(problems, problem{
			reason: "WebhookReceiverConfiguredButNotEnabled",
			message: fmt.Sprintf("spec.webhookReceiver is set but %q is not listed in providers - "+
				"authenticated requests are accepted but every signal is filtered, producing no Finding",
				webhook.ProviderName),
		})
	}

	condition := metav1.Condition{
		Type:               "Ready",
		ObservedGeneration: policy.Generation,
	}
	switch len(problems) {
	case 0:
		condition.Status = metav1.ConditionTrue
		condition.Reason = "Active"
		condition.Message = fmt.Sprintf("watching providers: %s", strings.Join(policy.Spec.Providers, ", "))
	case 1:
		condition.Status = metav1.ConditionFalse
		condition.Reason = problems[0].reason
		condition.Message = problems[0].message
	default:
		messages := make([]string, len(problems))
		for i, p := range problems {
			messages[i] = p.message
		}
		condition.Status = metav1.ConditionFalse
		condition.Reason = "Misconfigured"
		condition.Message = strings.Join(messages, "; ")
	}

	meta.SetStatusCondition(&policy.Status.Conditions, condition)
	if err := r.Status().Update(ctx, policy); err != nil {
		log.Error(err, "Failed to update SignalPolicy status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SignalPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&candorv1alpha1.SignalPolicy{}).
		Named("signalpolicy").
		Complete(r)
}
