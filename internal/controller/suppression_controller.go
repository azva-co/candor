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

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
)

// conditionExpired mirrors whether Suppression.spec.expiresAt has passed - the only state this
// reconciler manages. Actually applying (or lifting) suppression on a Finding is
// FindingReconciler's job (internal/signal.FindActiveSuppression already re-checks expiry itself
// on every Finding reconcile); this condition exists purely so `kubectl get suppressions` shows
// that a Suppression has lapsed without an operator comparing timestamps by hand.
const conditionExpired = "Expired"

// SuppressionReconciler reconciles a Suppression object
type SuppressionReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=candor.dev,resources=suppressions,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=candor.dev,resources=suppressions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=candor.dev,resources=suppressions/finalizers,verbs=update

func (r *SuppressionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	suppression := &candorv1alpha1.Suppression{}
	if err := r.Get(ctx, req.NamespacedName, suppression); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if suppression.Spec.ExpiresAt == nil {
		return ctrl.Result{}, nil
	}

	now := time.Now()
	expired := !suppression.Spec.ExpiresAt.After(now)

	condition := metav1.Condition{
		Type:               conditionExpired,
		ObservedGeneration: suppression.Generation,
	}
	if expired {
		condition.Status = metav1.ConditionTrue
		condition.Reason = "PastExpiresAt"
		condition.Message = "expiresAt has passed - this Suppression no longer mutes anything"
	} else {
		condition.Status = metav1.ConditionFalse
		condition.Reason = "NotYetExpired"
		condition.Message = "still active"
	}

	changed := meta.SetStatusCondition(&suppression.Status.Conditions, condition)
	if changed {
		if err := r.Status().Update(ctx, suppression); err != nil {
			return ctrl.Result{}, err
		}
	}

	if expired {
		return ctrl.Result{}, nil
	}
	// Requeue exactly when it lapses, so the Expired condition flips without waiting on some
	// other event to touch this object first.
	return ctrl.Result{RequeueAfter: time.Until(suppression.Spec.ExpiresAt.Time)}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SuppressionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&candorv1alpha1.Suppression{}).
		Named("suppression").
		Complete(r)
}
