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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
)

// OperatingPolicyReconciler reconciles a OperatingPolicy object. Like SignalPolicyReconciler, this
// is validation-only - the actual budget accounting happens inline in
// internal/signal.CheckGlobalPullRequestBudget, called directly by FindingReconciler, the same
// separation SignalPolicy's own Budget/PullRequestBudget already use.
type OperatingPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Recorder emits a K8s Event on every Mode transition - docs/design.md's brake definition
	// requires the panic switch be "visible in status and Events", not status alone. Defaulted in
	// SetupWithManager if unset.
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=candor.dev,resources=operatingpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=candor.dev,resources=operatingpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=candor.dev,resources=operatingpolicies/finalizers,verbs=update

// Reconcile flags the one misconfiguration specific to a singleton resource: more than one
// OperatingPolicy existing in the cluster. See that type's doc comment for why only one is
// meaningful - internal/signal.FindOperatingPolicy takes the first by name and silently ignores
// the rest, so a second object having no visible effect is exactly the kind of quiet failure this
// reconciler exists to surface instead.
func (r *OperatingPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	policy := &candorv1alpha1.OperatingPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	all := &candorv1alpha1.OperatingPolicyList{}
	if err := r.List(ctx, all); err != nil {
		return ctrl.Result{}, err
	}

	condition := metav1.Condition{Type: "Ready", ObservedGeneration: policy.Generation}
	if len(all.Items) > 1 {
		condition.Status = metav1.ConditionFalse
		condition.Reason = "MultipleObjects"
		condition.Message = "more than one OperatingPolicy exists in the cluster - only one is meaningful, and which one takes effect is unspecified"
	} else {
		condition.Status = metav1.ConditionTrue
		condition.Reason = "Active"
		condition.Message = "governing the cluster-wide pull request rate limit"
	}
	meta.SetStatusCondition(&policy.Status.Conditions, condition)

	// currentMode falls back to OperatingModeActive for an object that predates this field, or
	// was written by something that skipped CRD defaulting (e.g. a raw client in a test) -
	// matches internal/signal.InAuditMode's own stance that only an explicit "Audit" counts.
	currentMode := policy.Spec.Mode
	if currentMode == "" {
		currentMode = candorv1alpha1.OperatingModeActive
	}
	if previous := policy.Status.ObservedMode; previous != "" && previous != currentMode {
		eventType := corev1.EventTypeNormal
		if currentMode == candorv1alpha1.OperatingModeAudit {
			eventType = corev1.EventTypeWarning
		}
		r.Recorder.Eventf(policy, eventType, "ModeChanged", "operating mode changed from %s to %s", previous, currentMode)
	}
	policy.Status.ObservedMode = currentMode

	if err := r.Status().Update(ctx, policy); err != nil {
		log.Error(err, "Failed to update OperatingPolicy status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *OperatingPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorderFor("candor") //nolint:staticcheck
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&candorv1alpha1.OperatingPolicy{}).
		Named("operatingpolicy").
		Complete(r)
}
