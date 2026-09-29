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

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	candorv1alpha1 "github.com/azva-co/candor/api/v1alpha1"
	"github.com/azva-co/candor/internal/controller"
	"github.com/azva-co/candor/internal/gitops"
	"github.com/azva-co/candor/internal/llm"
	"github.com/azva-co/candor/internal/llm/anthropic"
	"github.com/azva-co/candor/internal/llm/ollama"
	"github.com/azva-co/candor/internal/metrics"
	"github.com/azva-co/candor/internal/provider"
	"github.com/azva-co/candor/internal/provider/trivy"
	signalwebhook "github.com/azva-co/candor/internal/provider/webhook"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(candorv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

// managerClientOptions configures the manager's client to never cache Secrets. The manager's
// default client caches every type it reads via a List+Watch informer, but Secrets are read by
// name only (GitOpsRepo.SecretRef, WebhookReceiver.SecretRef) - the ServiceAccount deliberately
// has no cluster-wide list/watch on Secrets (KSV-0041; a namespaced Role grants get on one named
// Secret only), so a cached Get would block forever waiting for an informer sync that can never
// succeed. Confirmed for real against a live cluster (not caught by any fake-client or
// envtest-with-admin-creds test, which bypass RBAC entirely): the reflector logs "secrets is
// forbidden ... at the cluster scope" and retries indefinitely, hanging every caller of a cached
// Secret Get, including the webhook receiver and the pre-existing GitOpsRepo path, silently, with
// no timeout.
//
// Extracted to a named value, not inlined into the ctrl.NewManager call below, so
// main_test.go's regression test (issue #58) verifies the exact configuration shipped, not a
// hand-copied duplicate that could silently drift from it.
var managerClientOptions = client.Options{
	Cache: &client.CacheOptions{DisableFor: []client.Object{&corev1.Secret{}}},
}

// nolint:gocyclo
func main() {
	var metricsAddr string
	var metricsCertPath, metricsCertName, metricsCertKey string
	var webhookCertPath, webhookCertName, webhookCertKey string
	var webhookPort int
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var tlsOpts []func(*tls.Config)
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.IntVar(&webhookPort, "webhook-port", 9443, "Port the webhook server listens on. "+
		"Defaults to 9443. Set -1 to disable the webhook server.")
	var signalReceiverPort int
	flag.IntVar(&signalReceiverPort, "signal-receiver-port", 9444, "Port the generic inbound signal "+
		"receiver listens on (internal/provider/webhook - unrelated to the admission webhook server "+
		"above, which speaks AdmissionReview, not signal payloads). Set 0 to disable it.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("Disabling HTTP/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	// Initial webhook TLS options
	webhookTLSOpts := tlsOpts
	webhookServerOptions := webhook.Options{
		TLSOpts: webhookTLSOpts,
		Port:    webhookPort,
	}

	if len(webhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", webhookCertPath, "webhook-cert-name", webhookCertName, "webhook-cert-key", webhookCertKey)

		webhookServerOptions.CertDir = webhookCertPath
		webhookServerOptions.CertName = webhookCertName
		webhookServerOptions.KeyName = webhookCertKey
	}

	webhookServer := webhook.NewServer(webhookServerOptions)

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.25.0/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}

	if secureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.25.0/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	// If the certificate is not specified, controller-runtime will automatically
	// generate self-signed certificates for the metrics server. While convenient for development and testing,
	// this setup is not recommended for production.
	if len(metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName, "metrics-cert-key", metricsCertKey)

		metricsServerOptions.CertDir = metricsCertPath
		metricsServerOptions.CertName = metricsCertName
		metricsServerOptions.KeyName = metricsCertKey
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Client:                 managerClientOptions,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "afe5e50e.candor.dev",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "Failed to start manager")
		os.Exit(1)
	}

	// A collector, not a package-level metric var like the rest of internal/metrics - it computes
	// candor_findings_current fresh from the manager's cached client on every scrape, the same
	// pattern kube-state-metrics uses for "current count of X" metrics a plain counter can't
	// express correctly.
	ctrlmetrics.Registry.MustRegister(&metrics.FindingsCollector{Reader: mgr.GetClient()})

	if err := (&controller.SignalPolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "signalpolicy")
		os.Exit(1)
	}
	// No backend configured is a supported configuration (deterministic findings only, no LLM
	// cost) - not an error. See FindingReconciler.LLM's doc comment. CANDOR_LLM_PROVIDER defaults
	// to "anthropic" so existing deployments (predating Ollama support) are unaffected.
	var llmClient llm.Client
	llmProvider := os.Getenv("CANDOR_LLM_PROVIDER")
	if llmProvider == "" {
		llmProvider = "anthropic"
	}
	switch llmProvider {
	case "anthropic":
		if apiKey := os.Getenv("ANTHROPIC_API_KEY"); apiKey != "" {
			llmModel := anthropic.DefaultModel
			var opts []anthropic.Option
			if m := os.Getenv("CANDOR_LLM_MODEL"); m != "" {
				llmModel = m
				opts = append(opts, anthropic.WithModel(m))
			}
			llmClient = anthropic.New(apiKey, opts...)
			setupLog.Info("LLM enrichment enabled", "provider", "anthropic", "model", llmModel)
		} else {
			setupLog.Info("ANTHROPIC_API_KEY not set - LLM enrichment disabled, deterministic findings only")
		}
	case "ollama":
		llmModel := ollama.DefaultModel
		var opts []ollama.Option
		if m := os.Getenv("CANDOR_LLM_MODEL"); m != "" {
			llmModel = m
			opts = append(opts, ollama.WithModel(m))
		}
		llmHost := os.Getenv("CANDOR_OLLAMA_HOST")
		llmClient = ollama.New(llmHost, opts...)
		if llmHost == "" {
			llmHost = ollama.DefaultHost
		}
		setupLog.Info("LLM enrichment enabled", "provider", "ollama", "model", llmModel, "host", llmHost)
	default:
		setupLog.Error(nil, "Unknown CANDOR_LLM_PROVIDER - must be \"anthropic\" or \"ollama\"", "value", llmProvider)
		os.Exit(1)
	}

	if err := (&controller.FindingReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		LLM:    llmClient,
		// Unlike LLM, this is always wired up rather than gated on an env var: neither backend has
		// a global "enabled" concept of its own - ProposePullRequest only ever activates
		// per-namespace, opt-in, via that namespace's own SignalPolicy.Spec.GitOpsRepo, and which
		// backend within that is GitOpsRepo.Provider's own choice, not this wiring's.
		GitOps: &gitops.MultiOpener{GitHub: &gitops.GitHubOpener{}, GitLab: &gitops.GitLabOpener{}},
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "finding")
		os.Exit(1)
	}
	if err := (&controller.SuppressionReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "suppression")
		os.Exit(1)
	}
	// The VulnerabilityReport CRD belongs to Trivy Operator, not Candor - a cluster without it
	// installed is a normal, supported configuration (this provider is optional), not an error.
	// Registering a watch for a CRD that doesn't exist would crash the whole manager, taking down
	// every other controller with it, so this is checked before SetupWithManager rather than
	// letting that happen.
	if installed, err := provider.CRDInstalled(mgr.GetRESTMapper(), trivy.GroupVersionKind); err != nil {
		setupLog.Error(err, "Failed to check whether the VulnerabilityReport CRD is installed")
		os.Exit(1)
	} else if !installed {
		setupLog.Info("VulnerabilityReport CRD not found - skipping the Trivy provider (install Trivy Operator to enable it)")
	} else if err := (&trivy.Reconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "trivy-provider")
		os.Exit(1)
	}
	if err := (&controller.OperatingPolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "operatingpolicy")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	digestInterval := 24 * time.Hour
	if v := os.Getenv("CANDOR_DIGEST_INTERVAL"); v != "" {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			setupLog.Error(err, "invalid CANDOR_DIGEST_INTERVAL, falling back to default", "value", v, "default", digestInterval)
		} else {
			digestInterval = parsed
		}
	}
	if err := mgr.Add(&controller.DigestRunnable{Client: mgr.GetClient(), Interval: digestInterval}); err != nil {
		setupLog.Error(err, "Failed to add digest runnable")
		os.Exit(1)
	}

	if signalReceiverPort > 0 {
		receiver := &signalwebhook.Receiver{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
			Addr:   fmt.Sprintf(":%d", signalReceiverPort),
		}
		if err := mgr.Add(receiver); err != nil {
			setupLog.Error(err, "Failed to add webhook signal receiver")
			os.Exit(1)
		}
		setupLog.Info("Webhook signal receiver enabled", "port", signalReceiverPort)
	} else {
		setupLog.Info("signal-receiver-port is 0 - webhook signal receiver disabled")
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("Starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "Failed to run manager")
		os.Exit(1)
	}
}
