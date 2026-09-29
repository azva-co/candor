package trivy

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/azva-co/candor/internal/signal"
)

// Reconciler watches VulnerabilityReport objects and turns each one into a Finding via
// signal.Ingest. It never writes back to the VulnerabilityReport itself, and its RBAC below is
// read-only on that type by construction - see docs/design.md pillar 1.
type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=aquasecurity.github.io,resources=vulnerabilityreports,verbs=get;list;watch

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(GroupVersionKind)
	if err := r.Get(ctx, req.NamespacedName, u); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	sig, ok, err := translate(u)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("translating VulnerabilityReport %s: %w", req.NamespacedName, err)
	}
	if !ok {
		return ctrl.Result{}, nil
	}

	result, err := signal.Ingest(ctx, r.Client, r.Scheme, sig, u)
	if err != nil {
		return ctrl.Result{}, err
	}
	log.V(1).Info("Ingested Trivy signal", "result", result, "severity", sig.Severity, "resource", sig.Namespace+"/"+sig.Name)

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager. Watches VulnerabilityReport as an
// unstructured type - no compile-time dependency on Trivy Operator's Go module, matching the
// provider pattern's loose coupling.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(GroupVersionKind)

	return ctrl.NewControllerManagedBy(mgr).
		For(u).
		Named("trivy-provider").
		Complete(r)
}
