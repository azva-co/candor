# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0](https://github.com/teerakarna/candor/compare/v0.1.0...v0.2.0) (2026-09-30)


### Added

* add GitLab GitOps backend (slice 11) ([#89](https://github.com/teerakarna/candor/issues/89)) ([de8514d](https://github.com/teerakarna/candor/commit/de8514d778a47a1d4af9d7c5d3889739c33f6564))
* automate versioning with release-please ([#96](https://github.com/teerakarna/candor/issues/96)) ([f8d81b6](https://github.com/teerakarna/candor/commit/f8d81b65d71f4de73c23e2bb838bf577639eb0d5))
* generic webhook signal receiver, completing slice 10 ([#65](https://github.com/teerakarna/candor/issues/65)) ([abac8c6](https://github.com/teerakarna/candor/commit/abac8c6afd4f1e8abe43321d299227dde206969b))
* Ollama LLM backend with backend-agnostic action validation ([#56](https://github.com/teerakarna/candor/issues/56)) ([046904e](https://github.com/teerakarna/candor/commit/046904eef70f279f9dfdb2ffa6ae162feb44bdf8))

## [Unreleased]

## [0.1.0] - 2026-09-24

First tagged release. Slices 1-9 of the delivery plan in `docs/design.md`: signal ingestion,
bounded LLM enrichment, suppression, the verification loop, notifications, and the GitOps pull
request action with all of its brakes. Deliberately `v0.1.0`, not `v1.0.0` - the CRD shapes are
still `v1alpha1` and may change, and nothing here has yet been run against a production cluster.

### Added

- Project scaffolding (kubebuilder), CI, OSS boilerplate, release automation, repo governance.
- `SignalPolicy` and `Finding` CRDs with real fields (deterministic slice only — no LLM yet).
  `Suppression` remains scaffolded, not yet implemented (a later slice).
- First signal provider: Trivy Operator `VulnerabilityReport` → `Finding`, gated by a
  `SignalPolicy` in the same namespace. Read-only RBAC on the external CRD; skips registering
  itself (rather than crashing the manager) if Trivy Operator isn't installed.
- Content-addressed fingerprinting (`Finding.status.fingerprint`): the core cost-accountability
  mechanism (docs/design.md pillar 2). Re-ingesting unchanged content never looks new, and content
  actually changing makes a settled Finding "need enrichment" again. No LLM call exists yet to
  gate (slice 4) - this slice proves the mechanism the real gate gets built directly on top of.
- LLM enrichment (`internal/llm`, `internal/llm/anthropic`): `FindingReconciler` calls Anthropic
  exactly once per distinct fingerprint, gated by the mechanism from the previous entry - the
  actual "N reconciles, one call" claim is now a passing test, not just a design intention.
  Response is grammar-constrained to ranked hypotheses with confidence via Anthropic's structured
  outputs - never a single asserted cause, and no free-form output path for injected scanner data
  to escape through. Opt-in: no `ANTHROPIC_API_KEY` means deterministic findings only, a fully
  supported configuration, not a degraded one.
- Budget ceiling on LLM enrichment spend: `SignalPolicy.spec.budget` (max calls per rolling window,
  optional - unlimited if omitted). On exhaustion, enrichment degrades to deterministic-only
  findings (not an error) and a Warning Event fires on the `SignalPolicy`. Self-observability via
  four Prometheus metrics (`candor_llm_calls_total`, `candor_enrichment_skipped_total`,
  `candor_signalpolicy_budget_calls_used`, `candor_signalpolicy_budget_calls_limit`) exposed on the
  existing manager metrics endpoint - proven with real metric-value assertions, and a test proving a
  budget of 2 caps real LLM calls to exactly 2 across 5 distinct Findings.
- `Suppression` CRD: mute a Finding by its exact content fingerprint (`spec.fingerprint`), with a
  required `spec.reason` and optional `spec.expiresAt`. Exact by construction - if the underlying
  content actually changes, the fingerprint changes too and the Finding resurfaces on its own, no
  separate "resolved" tracking needed. Applies before the LLM gate, so it works even with no LLM
  configured. `FindingReconciler` now watches `Suppression` objects directly, so create/edit/delete
  takes effect immediately rather than waiting on the next unrelated Finding event.
- Verification loop: `Finding.status.verificationOutcome` (StillPresent/Resolved/Recurred),
  re-checked by `internal/signal.Ingest` every time a Finding's source is reconciled. A Trivy
  `VulnerabilityReport` that drops to zero vulnerabilities (or below every `SignalPolicy`'s
  threshold) now resolves its Finding instead of leaving it showing stale severity forever; a
  resolved Finding whose source produces a real signal again is marked Recurred. Published as
  `candor_verification_transitions_total` (by outcome) - the resolved:recurred ratio over time is
  Candor's accuracy signal.
- Grafana dashboard (`charts/chart/files/grafana-dashboard.json`), shipped as a ConfigMap behind
  `grafanaDashboard.enabled` (off by default), labelled for the kube-prometheus-stack Grafana
  sidecar to auto-discover. Plots LLM calls, enrichment skipped by reason, verification
  transitions, budget usage, and the enrichment-calls-avoided ratio.
- Generic webhook sink (`internal/notify`) + periodic digest: `SignalPolicy.spec.webhook.url`
  (optional, one URL per namespace) drives both an immediate notification on a Finding created,
  resolved, or recurred, and a periodic per-namespace digest (`CANDOR_DIGEST_INTERVAL`, default
  24h) tallying Findings by verification outcome and severity. Both are best-effort - a failure is
  logged and counted (`candor_webhook_sends_total`), never returned as an error.
- `candor_findings_current{namespace,severity,outcome}`: a live gauge (Prometheus `Collector`,
  computed fresh on every scrape from the manager's cached client, not a package-level counter
  like every other metric here) reporting how many Findings currently exist per severity and
  verification outcome. None of the existing metrics could answer "how many findings are open
  right now" - they're all transition counters or self-observability. This is the metric behind
  the redesigned dashboard's landing status tiles.
- `candor_verification_transitions_total` now also carries a `severity` label (previously
  `outcome` only), so Resolved/Recurred can be broken down per severity, not just in aggregate.
- Redesigned Grafana dashboard: leads with four colour-coded severity tiles (Critical/High/Medium/
  Low), each split into three stacked bands - Outstanding, Resolved (7d), Recurred (7d) - so the
  first thing an operator sees is what needs action, what's been taken care of, and what's come
  back, not Candor's own cost metrics. `Resolved`/`Recurred` counts are floored (`floor(...)`),
  not rounded: `increase()` over a partial window can extrapolate a fractional value, and rounding
  up would claim an event happened that isn't actually confirmed yet. Historical trends and
  cost/operator-health panels (LLM calls, budget usage, enrichment-avoidance ratio) are still
  present, grouped under labelled rows, as drill-down rather than the first view.

- `ProposePullRequest` (slice 9), the first mechanism that writes anything outward: the LLM
  recommends `Notify` or `ProposePullRequest` per hypothesis (grammar-constrained to that closed
  catalog - it never authorizes a write on its own), but `internal/gitops.ComputeFix`
  independently, mechanically verifies a fix actually exists before anything happens - for a Trivy
  `VulnerabilityReport`, only when every reported vulnerability agrees on one `fixedVersion`. No
  such fix, no PR, regardless of what the model recommended. `internal/gitops.GitHubOpener` opens
  the PR: branches, patches one YAML path, commits, and carries the finding plus ranked hypotheses
  in the PR body - "the pull request is also a report."
- `SignalPolicy.spec.gitOpsRepo` + `spec.pullRequestBudget`: the per-namespace cap on
  `ProposePullRequest`. Unlike the LLM budget, omitting it never means unlimited - a conservative
  built-in default (1 PR/24h) applies instead, so the action can't ship without a brake in the same
  change (docs/design.md, "every accelerator ships with its brake").
- `OperatingPolicy`: Candor's first cluster-scoped CRD, a deliberate singleton. Its
  `spec.pullRequestRateLimit` bounds `ProposePullRequest` across every namespace, checked in
  addition to and after the per-namespace budget - a namespace comfortably under its own cap can
  still be refused once the cluster-wide ceiling is spent by everyone else. Unlike every other
  budget here, no `OperatingPolicy` existing at all denies rather than defaulting to a number -
  there's no object to persist a count against, so allowing anyway would just be an uncounted brake.
- `OperatingPolicy.spec.mode` (`Active`/`Audit`): the CRD-reachable panic switch, checked before
  either budget or the fix computation, so flipping to `Audit` is a genuine full stop, not "still
  counted but not executed". `OperatingPolicyReconciler` emits a `ModeChanged` Event on every real
  transition (visible in status and Events, per the brake definition, not status alone).
- All three brakes above are volume-tested through the real reconciler, not just asserted: N
  distinct Findings against a small per-namespace ceiling, two namespaces each under their own
  budget but exceeding a shared global one, and flipping to `Audit` mid-run rather than starting
  there - the same "prove it holds under real volume" standard
  `TestFindingReconciler_BudgetCostRegression` set for the LLM budget.

### Fixed

- `candor_enrichment_skipped_total{reason=no_llm_configured}` is now actually incremented - it was
  documented in the metric's help text since the budget-ceiling slice but never wired up.
- Pull request budget could be exhausted without ever opening a PR: both new budgets persisted
  their spend the moment they allowed an attempt, not on actual success, so a misconfigured
  `gitOpsRepo` Secret (missing, wrong key) failed identically on every retry and silently burned
  the whole allowance - as low as 1 PR/24h by default - with zero PRs ever opened. The Secret is
  now validated before either budget is touched, and branch creation is idempotent so a retry after
  an earlier partial failure doesn't fail forever either.

### Security

- Dropped a cluster-wide `get` on Secrets from the controller's ClusterRole, caught by Trivy's
  config scan (KSV-0041) before merge - equivalent to cluster-admin in most clusters, since it
  could read every Secret in the cluster, not just the one `gitOpsRepo` needs. A namespace enabling
  `gitOpsRepo` now grants the controller's ServiceAccount a namespaced Role naming that one Secret
  explicitly, the same opt-in-per-namespace posture `SignalPolicy` itself already requires.

### Dev tooling

- CI now imports `charts/chart/files/grafana-dashboard.json` into a real Grafana instance
  (`grafana-dashboard` job) and checks every panel round-trips - catches the file failing to parse
  or the import silently dropping panels. Grafana's save API doesn't validate panel/query
  correctness, so this is a structural check, not full schema validation.
- `hack/grafana-preview/`: a `docker compose` stack (fake metrics generator + Prometheus + Grafana,
  both auto-provisioned) for visually checking the dashboard locally without a real cluster or
  operator - see its README.
- `render-diagrams.yml`: renders `docs-site/docs/assets/*.mmd` and fails the check if the checked-
  in SVG doesn't match, with instructions to regenerate locally. Originally auto-committed the
  render back to the branch; changed after that produced an unsigned bot commit that silently
  blocked merging under this repo's required-signed-commits branch protection, on a completely
  green PR - a bot can't cleanly sign its own commits without a real key in CI, so failing with
  instructions is simpler and just as effective.
- `make dev-up`/`dev-status`/`dev-down`: a persistent local Kind cluster, separate from the
  ephemeral one `make test-e2e` creates and destroys around itself. Installs Candor's CRDs plus the
  pinned Trivy `VulnerabilityReport` CRD (so a hand-crafted report works without a real Trivy
  Operator), builds the image, and deploys it - safe to re-run after a code change to rebuild and
  redeploy onto the same cluster.
- e2e smoke test: applies a real `SignalPolicy` and a schema-validated `VulnerabilityReport`, waits
  for a `Finding` to appear. Every other e2e check proves the manager comes up; this is the first
  one that proves the actual ingest-to-Finding pipeline works, not just that the pod is running.
