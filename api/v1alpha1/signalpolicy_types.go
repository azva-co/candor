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

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// SignalPolicySpec defines the desired state of SignalPolicy.
//
// A SignalPolicy governs signals in its own namespace only - the same convention as
// ResourceQuota, LimitRange, and NetworkPolicy. There is no cross-namespace targeting field;
// a team opts a namespace in by creating a SignalPolicy inside it, and RBAC on SignalPolicy
// itself controls who can do that.
type SignalPolicySpec struct {
	// providers this policy enables, e.g. ["trivy"]. Deliberately a free-form string list rather
	// than a closed CRD enum: each provider's own reconciler simply ignores policies that don't
	// name it, so adding a new provider later never requires a schema migration here.
	// +kubebuilder:validation:MinItems=1
	Providers []string `json:"providers"`

	// minSeverity is the minimum signal severity that produces a Finding. Signals below this
	// threshold are ignored entirely - they never reach a Finding at all, so they can't
	// contribute noise even before suppression exists (see docs/design.md pillar 3).
	// +kubebuilder:validation:Enum=LOW;MEDIUM;HIGH;CRITICAL
	// +kubebuilder:default=HIGH
	// +optional
	MinSeverity string `json:"minSeverity,omitempty"`

	// budget bounds LLM enrichment spend for this policy's namespace over a rolling window.
	// Optional - omitted means unlimited, relying entirely on the fingerprint gate (slice 3) to
	// bound cost. When the limit is reached, enrichment degrades to deterministic-only findings
	// until the window resets - it never silently keeps spending past the ceiling.
	// +optional
	Budget *Budget `json:"budget,omitempty"`

	// webhook configures a generic JSON sink for this namespace - the same URL is used both for
	// immediate notifications (a Finding created, resolved, or recurred) and the periodic digest
	// (docs/design.md: "one code path covers Slack/Teams/PagerDuty/anything" - a single generic
	// payload shape, not a per-vendor integration). Optional - omitted means no notifications and
	// no digest for this namespace.
	// +optional
	Webhook *Webhook `json:"webhook,omitempty"`

	// gitOpsRepo configures the GitOps repository ProposePullRequest writes to. Optional - omitted
	// means ProposePullRequest is never selectable for this namespace's Findings, regardless of
	// what a Hypothesis recommends - the same "not configured, so skip" stance Budget and Webhook
	// already take.
	// +optional
	GitOpsRepo *GitOpsRepo `json:"gitOpsRepo,omitempty"`

	// pullRequestBudget bounds ProposePullRequest actions for this policy's namespace over a
	// rolling window. Unlike Budget (which may legitimately be unlimited, relying on the
	// fingerprint gate to bound LLM cost), this is never unlimited when GitOpsRepo is set:omitting
	// it does not mean "no cap", it means "the conservative built-in default applies" (see
	// internal/signal.CheckPullRequestBudget) - docs/design.md:189 is explicit that
	// ProposePullRequest "does not ship without" a cap in the same change, so there is no
	// configuration that leaves this action uncapped.
	// +optional
	PullRequestBudget *PullRequestBudget `json:"pullRequestBudget,omitempty"`

	// webhookReceiver enables the generic inbound signal receiver for this namespace (the
	// "webhook" provider - docs/design.md's Signal providers, slice 10). Optional - omitted means
	// this namespace's receiver endpoint always rejects, regardless of what's posted to it. Unlike
	// every other guardrail in Candor, there is no conservative default here: an unauthenticated
	// receiver that can create Findings is a spoofing vector, not a lesser version of the feature,
	// so "not configured" fails closed rather than open.
	// +optional
	WebhookReceiver *WebhookReceiver `json:"webhookReceiver,omitempty"`
}

// GitOpsProvider selects which git hosting backend a GitOpsRepo targets.
// +kubebuilder:validation:Enum=github;gitlab
type GitOpsProvider string

const (
	GitOpsProviderGitHub GitOpsProvider = "github"
	GitOpsProviderGitLab GitOpsProvider = "gitlab"
)

// GitOpsRepo identifies the GitOps repository and file ProposePullRequest patches, and how to
// authenticate to it. GitHub and GitLab are both supported (see Provider) via
// internal/gitops.Opener implementations behind a common interface - see #38's discussion for why
// that beats a generic git library for a capability nothing here asked for at the time.
type GitOpsRepo struct {
	// provider selects which git hosting backend this repository is on.
	// +kubebuilder:default=github
	// +optional
	Provider GitOpsProvider `json:"provider,omitempty"`

	// host overrides the provider's API base URL for a self-hosted instance (self-hosted GitLab,
	// GitHub Enterprise). Empty means the provider's public SaaS API. Restricted to http(s) URLs -
	// this only rejects an obviously malformed value at admission time, it is not a substitute for
	// namespace-level RBAC on who may create a SignalPolicy: the controller sends that namespace's
	// GitOps token to whatever host is named here.
	// +kubebuilder:validation:Pattern=`^https?://.+$`
	// +optional
	Host string `json:"host,omitempty"`

	// owner is the GitHub organisation/user or GitLab namespace that owns the repository, e.g.
	// "azva-co". GitLab supports nested subgroups - for a project inside one, set this to the full
	// namespace path, e.g. "group/subgroup".
	// +required
	Owner string `json:"owner"`

	// repo is the repository (GitHub) or project (GitLab) name, e.g. "gitops-demo".
	// +required
	Repo string `json:"repo"`

	// baseBranch is the branch ProposePullRequest branches from and opens its PR against.
	// +kubebuilder:default="main"
	// +optional
	BaseBranch string `json:"baseBranch,omitempty"`

	// path is the file within the repository that carries the image tag to patch, e.g.
	// "apps/api/values.yaml".
	// +required
	Path string `json:"path"`

	// yamlPath is a dot-separated path to the tag field within the YAML document at Path, e.g.
	// "image.tag". Kept deliberately narrow to a single scalar replacement - not a general
	// templating or Kustomize/Helm-aware patch - because that's the only fix this slice computes
	// (see internal/gitops.ComputeFix); broader patch generation is out of scope until a real need
	// for it exists.
	// +required
	YAMLPath string `json:"yamlPath"`

	// secretRef names a Secret in this SignalPolicy's namespace holding a token with contents and
	// pull/merge-request write access to Repo, under the key "token" - a GitHub personal access
	// token or GitLab personal/project access token, matching Provider.
	//
	// The controller's ClusterRole deliberately grants no cluster-wide access to Secrets (KSV-0041:
	// that would be equivalent to cluster-admin in most clusters). Setting GitOpsRepo requires this
	// namespace to also grant the controller's ServiceAccount a namespaced Role naming this one
	// Secret - the same opt-in-per-namespace posture SignalPolicy itself already requires.
	// +required
	SecretRef corev1.LocalObjectReference `json:"secretRef"`
}

// PullRequestBudget bounds ProposePullRequest actions over a rolling window - the per-namespace
// brake docs/design.md:189 requires in the same change as the action itself.
type PullRequestBudget struct {
	// maxPullRequests is the maximum number of pull requests ProposePullRequest may open within
	// one window.
	// +kubebuilder:validation:Minimum=1
	// +required
	MaxPullRequests int32 `json:"maxPullRequests"`

	// windowSeconds is the rolling window length. Rolling from whenever the window last reset, not
	// calendar-aligned - matches Budget.WindowSeconds for the same reason.
	// +kubebuilder:validation:Minimum=60
	// +kubebuilder:default=86400
	// +optional
	WindowSeconds int32 `json:"windowSeconds,omitempty"`
}

// WebhookReceiver authenticates inbound POSTs to this namespace's generic signal receiver
// endpoint. Distinct from Webhook, which is the outbound notification sink - this is the inbound
// counterpart, for tools that don't expose a Kubernetes CRD the way Trivy Operator does but can
// already POST an event on their own (SonarQube on analysis completion, Falco via falcosidekick).
type WebhookReceiver struct {
	// secretRef names a Secret in this SignalPolicy's namespace holding the HMAC signing key under
	// the key "secret". Every request must carry an X-Candor-Signature header
	// ("sha256=<hex-encoded HMAC-SHA256 of the raw request body>") verified against this key -
	// same namespaced-Role opt-in posture as GitOpsRepo.SecretRef (no cluster-wide Secret access).
	// +required
	SecretRef corev1.LocalObjectReference `json:"secretRef"`
}

// Webhook is a generic JSON notification sink.
type Webhook struct {
	// url receives an HTTP POST with a JSON body on every notification and digest. Must be
	// http:// or https:// - checked at send time (internal/notify.Send), not admission time, to
	// keep the schema simple.
	// +required
	URL string `json:"url"`
}

// Budget bounds LLM enrichment calls over a rolling window.
type Budget struct {
	// maxCalls is the maximum number of LLM enrichment calls allowed within one window.
	// +kubebuilder:validation:Minimum=1
	// +required
	MaxCalls int32 `json:"maxCalls"`

	// windowSeconds is the rolling window length. Rolling from whenever the window last reset,
	// not calendar-aligned - simpler to reason about, no timezone/cron edge cases.
	// +kubebuilder:validation:Minimum=60
	// +kubebuilder:default=86400
	// +optional
	WindowSeconds int32 `json:"windowSeconds,omitempty"`
}

// SignalPolicyStatus defines the observed state of SignalPolicy.
type SignalPolicyStatus struct {
	// budgetWindowStart is when the current budget window began. Unset means no window is active
	// yet - no enrichment call has been checked against this policy's budget since the last reset.
	// +optional
	BudgetWindowStart *metav1.Time `json:"budgetWindowStart,omitempty"`

	// budgetCallsUsed is the number of LLM calls made within the current budget window.
	// +optional
	BudgetCallsUsed int32 `json:"budgetCallsUsed,omitempty"`

	// pullRequestWindowStart is when the current pull request budget window began. Unset means no
	// window is active yet - mirrors BudgetWindowStart for the same reason.
	// +optional
	PullRequestWindowStart *metav1.Time `json:"pullRequestWindowStart,omitempty"`

	// pullRequestsOpened is the number of pull requests ProposePullRequest has opened within the
	// current window.
	// +optional
	PullRequestsOpened int32 `json:"pullRequestsOpened,omitempty"`

	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	// conditions represent the current state of the SignalPolicy resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// Standard condition types include:
	// - "Available": the resource is fully functional
	// - "Progressing": the resource is being created or updated
	// - "Degraded": the resource failed to reach or maintain its desired state
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Providers",type=string,JSONPath=".spec.providers"
// +kubebuilder:printcolumn:name="MinSeverity",type=string,JSONPath=".spec.minSeverity"
// +kubebuilder:printcolumn:name="BudgetUsed",type=integer,JSONPath=".status.budgetCallsUsed"
// +kubebuilder:printcolumn:name="BudgetMax",type=integer,JSONPath=".spec.budget.maxCalls"
// +kubebuilder:printcolumn:name="Webhook",type=string,JSONPath=".spec.webhook.url"
// +kubebuilder:printcolumn:name="PRsOpened",type=integer,JSONPath=".status.pullRequestsOpened"
// +kubebuilder:printcolumn:name="PRsMax",type=integer,JSONPath=".spec.pullRequestBudget.maxPullRequests"

// SignalPolicy is the Schema for the signalpolicies API
type SignalPolicy struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of SignalPolicy
	// +required
	Spec SignalPolicySpec `json:"spec"`

	// status defines the observed state of SignalPolicy
	// +optional
	Status SignalPolicyStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// SignalPolicyList contains a list of SignalPolicy
type SignalPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SignalPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &SignalPolicy{}, &SignalPolicyList{})
		return nil
	})
}
