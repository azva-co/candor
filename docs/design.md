# Candor — design doc

## The thesis

Existing LLM-assisted Kubernetes ops tools (k8sgpt, Kubernaut, HolmesGPT, kagent) treat model
invocation as stateless, unbounded, and unaccountable. Candor treats it as a metered, verifiable
resource. Same job — ingest signals, use an LLM to enrich them, help DevOps/DevSecOps/SRE act on
them — engineered against the specific, evidenced failures the incumbents have in production.

This is a "same job, better engineering" bet (Rust to C++), not a novelty claim. The differentiation
is an architectural stance, not a feature list.

## Origin and prior art

This project's first draft was a spec for "KubeGuard" — provider-pattern signal ingestion (K8s
events, Trivy, Falco, Wiz, Prisma Cloud, Datadog CWS), a pluggable local/hosted LLM abstraction,
non-destructive quarantine, circuit breakers, and phased GitOps auto-remediation. That name collides
with three things, renamed to Candor: AppsCode's Guard
([kubeguard.dev](https://kubeguard.dev/), a Kubernetes auth webhook with a commercial offering),
a separate Java/Spring security scanner on GitHub, and
[arXiv 2509.04191](https://arxiv.org/abs/2509.04191), a paper on LLM-assisted Kubernetes hardening.
The earlier phrasing here listed "an enterprise product" and "an AppsCode auth tool" as separate
collisions; they are the same project.

Research before building found the exact job already has direct competitors.

> **Re-verified 2026-09-12.** This section was excluded from the gaps table's earlier verification
> pass and had decayed badly. The Kubernaut entry was substantively wrong, and the HolmesGPT quote
> was misattributed. Both corrected in place below.

- **[Kubernaut](https://github.com/jordigilh/kubernaut)** — closest analogue. Alert, LLM
  investigation, remediation, with approval gates, OPA policies and audit trails.
  **Its effectiveness monitor is no longer deferred.** DD-017 v1.0 (Dec 2025) deferred it entirely
  to V1.1, which is what this doc previously recorded. DD-017 v2.0 (Feb 2026) reversed that:
  **Level 1 (automated assessment) moved into V1.0 and has shipped**; only Level 2 (AI-powered
  analysis) remains V1.1, and it is Level 2 alone that needs 8+ weeks of remediation data. The
  project is at v1.6.0-rc12 (2026-09-11) and pushed to daily.
  The previous claim that it was "currently blocked by an unrelated TLS bug" is unsupported: the
  TLS items in its tracker are feature work (TLS-only listeners, mTLS ACLs), not a blocker.
  The previous claim that it is "the only OSS project with an outcome feedback loop" is an
  exclusivity assertion that was never verifiable and is dropped.

  **This weakens gap 4 below.** A competitor has shipped automated post-remediation effectiveness
  assessment. Candor's verification loop is no longer a differentiator by existence, only by shape
  (published as a metric, per-finding, in a single binary). Say that, not more.
- **[k8sgpt](https://github.com/k8sgpt-ai/k8sgpt) /
  [k8sgpt-operator](https://github.com/k8sgpt-ai/k8sgpt-operator)** — CNCF Sandbox, ~8k stars,
  actively maintained. Deterministic analyzers + LLM explanation. Its own issue tracker is the
  primary evidence base below.
- **[HolmesGPT](https://github.com/HolmesGPT/holmesgpt)** — read-only investigation, strong runbook
  integration, and a CNCF Sandbox project. "Without runbooks, the model just guesses" is a real
  quote and a good one, but it is **not HolmesGPT's own finding**, as this doc previously claimed:
  it comes from an SRE team at STCLab writing on the CNCF blog about running HolmesGPT against
  production EKS clusters. Attribute it to them, not to the project.
- **[kagent](https://github.com/kagent-dev/kagent)** — generic agent runtime, not a remediation
  product. Its human-in-the-loop writeup states the safety line this project also follows: "Fully
  autonomous agents are fine for read-only operations. For anything that changes state, you need a
  gate."

Given that, being *better* than these — not merely different — is the only defensible bar.

## What the original spec got right — kept

- **Provider pattern**: don't bundle Falco/Trivy inside the operator; consume their CRs and
  webhooks. Lightweight, no vendor lock-in.
- **Non-destructive quarantine**: strip the workload label so the Service stops routing, rather than
  killing the pod. Traffic stops, forensics survive.
- **Circuit breakers**: max-disruption percentage, global rate limit, a panic switch that drops to
  Audit mode and pages a human.
- **Audit-by-default**, and a hard rule that non-deterministic models never autonomously execute
  destructive actions.

## The eight gaps, and how Candor answers them

> **Citations re-verified 2026-09-12**, prompted by drafting a public blog post off this doc.
> Scope of that check: this gaps table, and the "trust problem" section below it. Four claims were
> wrong or overstated and are corrected in place, marked inline. Two could not be verified at all
> and were replaced with the weaker claim that *is* supported.
>
> **Not re-verified**: the "Origin and prior art" section above (only repo descriptions and star
> counts were spot-checked, not the specific claims about Kubernaut's internals or roadmap, some of
> which are time-sensitive), and the Palark review in row 8.
>
> The lesson is worth keeping: an evidence base decays. Issues get fixed and closed, and projects
> ship the thing you said they never shipped. **Re-check before citing any of this publicly.**

| # | Gap in the incumbents (evidenced) | Candor's answer |
|---|---|---|
| 1 | No cost model. k8sgpt-operator#769 (open): hourly scan configured, 164 findings, ~9,300 Bedrock calls in 3 days per CloudTrail. #730 (fixed Feb 2026): the mechanism behind that class of problem: change detection compared result hashes, found them identical, and updated anyway. Note the interval itself *was* being respected; the earlier claim here that it was ignored was wrong, corrected 2026-09-12 on re-verification. #419 (decouple LLM request timing from reconciles) sat 2+ years, closed Aug 2026 with "Closing as stale ... not on the current roadmap." | Content-addressed fingerprinting: hash (resource identity + relevant spec/status subset + analyzer verdict). LLM invoked **once per distinct fingerprint, ever**. Hard budget ceiling per window; on exhaustion, degrade to deterministic-only and say so. |
| 2 | No deduplication — an alert storm costs N× | Fingerprint collapses a storm to one enrichment call. |
| 3 | No suppression, so the tool recreates the fatigue it claims to fix. k8sgpt#372 ("Exclude a list of known issues") open since May 2023, still open, never shipped. Maintainer, ten days in: "We have no concensus on the design yet, do you want to propose something first?" (sic). A contributor offered a draft proposal; it never landed. Users were still asking in 2025. | `Suppression` CRD mutes a fingerprint with a required reason and optional expiry. Exact by construction — if the underlying state changes, the fingerprint changes and the finding resurfaces on its own. |
| 4 | Verification of remediation outcomes is partial, and this gap has narrowed since it was written (see "Origin and prior art": Kubernaut shipped Level 1 automated effectiveness assessment in V1.0, Feb 2026). k8sgpt-operator's `AUTO_REMEDIATION.md` checks Deployment rollout + replica availability before treating a finding as resolved, but lists "targeted re-analysis that proves the original finding is resolved" as future work, and states "a missing `Result` remains the finding-resolution signal", i.e. absence of a complaint is the proof. (Corrected 2026-09-12: the earlier claim that nothing is checked at all overstated this.) | Every finding carries a verification outcome (resolved / still-present / recurred / superseded), re-checked after state changes, exposed as metrics and status. |
| 5 | Writes to the cluster, which breaks GitOps shops. Structural, not anecdotal: Flux and ArgoCD revert drift from Git by design, so a direct cluster patch means two automated systems fighting over the same object. (A practitioner quote previously cited here could not be re-verified on 2026-09-12 and was removed; the structural argument stands on its own and needs no quote.) | Default write path is a **pull request** against the GitOps repo. Direct mutation only for resources not under GitOps management, gated behind Enforcing mode. |
| 6 | Prompt injection unaddressed, in a security tool | All ingested telemetry is untrusted input. Structured extraction before prompting; model output selects from a **fixed action catalog** — it can never emit a free-form action. |
| 7 | Weakest model shipped as default. arXiv 2509.04191 (the KubeGuard paper) benchmarks both on exactly these manifest-analysis tasks. GPT-4o: 0.929-1.00 F1 across the five tasks. Llama-3.1-8B: **0.504-0.808**, worst on NetworkPolicy Refinement (0.504 vs 0.961) and Role Creation (0.607 vs 1.00). (Corrected 2026-09-12: the earlier "0.79-0.81" figure cited here took only the model's two best scores and understated the real gap.) | Strong hosted model (Anthropic) as the v1 default. Per-model accuracy is measured and published against a fixture suite, not asserted. |
| 8 | No confidence modelling, no self-metrics, no least-privilege RBAC. Palark's k8sgpt review: non-deterministic recommendations across identical runs; once suggested rebooting the cluster; missed an initContainer `ErrImagePull`. | Ranked competing hypotheses with confidence, never one asserted cause. Full self-observability. Operator ServiceAccount is least-privilege, read-only by default, verified by a test that attempts a write and confirms denial. |

Plus a plain operational advantage: Kubernaut needs 9+ microservices. Candor is one operator binary
and a Helm chart — a difference in deployment and maintenance burden that users feel immediately.

## The trust problem this answers

- Majors & Hebert, SREcon25, ["AIOps: Prove It!"](https://www.usenix.org/conference/srecon25americas/presentation/majors) —
  an open letter asking vendors for "data on how often your system produces useful, actionable
  results." No OSS tool in this space has answered it.
- The Register with NeuBird AI, April 2026 (696 respondents): 60% cite lack of trust as the top
  AIOps adoption barrier (ROI, security and data quality each ~12-13%), 59% require near-perfect
  accuracy before adoption, and adoption matches that: 73% not using AIOps at all, 19% piloting,
  8% in production. (A "12% use AIOps day-to-day / 7.5% call it high-value" figure previously cited
  here could not be verified on 2026-09-12 and was replaced with these, which were.)
- "A single confident answer that's wrong is worse than no answer, because it sends a human down a
  road with the agent's credibility behind it." Commenter IgorVoytyuk on the
  [HyperProbe Launch HN thread](https://news.ycombinator.com/item?id=49185389), describing three
  incidents where confident-but-wrong diagnoses burned real debugging time. Verified verbatim
  2026-09-12.
- Model-routing economics generally: sending simple, deterministic checks to a cheap model and
  reserving the expensive one for reasoning-heavy work is widely reported to cut cost by roughly
  95%. (A specific LangChain anecdote previously cited here, "~20 Sonnet calls per health check
  run, collapsed to one Haiku call", could not be re-verified on 2026-09-12 and has been reduced
  to the general, corroborated claim. **Do not cite the specific version publicly without finding
  the source first.**) Candor's fingerprinting attacks the same cost problem structurally, so each
  integration does not have to rediscover it.

## Interaction surfaces

Operators surface through CRDs, metrics, and sinks. The projects that built a bespoke web UI
(kagent, Keep, NudgeBee) became multi-service platforms — exactly the complexity this project exists
to avoid. No UI, by design.

- **`Finding` CRD status** — primary surface, `kubectl get findings`.
- **Prometheus `/metrics`** — findings raised/suppressed/verified/recurred, LLM calls, tokens, spend
  vs. budget, degraded state.
- **Kubernetes Events** — picked up by whatever event exporter is already in the cluster.
- **Grafana dashboard**, shipped in the Helm chart. Not decoration — for a tool whose pitch is
  publishing its own accuracy, the dashboard is the proof surface.
- **Generic webhook sink** — one code path covers Slack/Teams/PagerDuty/anything, no per-vendor SDKs.
- **Periodic digest report** — a scheduled summary (findings raised/resolved/recurred, accuracy,
  spend vs. budget) over the webhook sink. This is the artifact the "Prove It!" critique asks for.
- **The pull request is also a report** — in GitOps mode, the PR body carries the finding, ranked
  hypotheses, confidence, and evidence. No new surface for a GitOps team to learn.

Non-goals: web UI, per-vendor chat integrations. An MCP server and a `kubectl candor` krew plugin
are plausible later additions, not v1.

## Architecture

- **Signal providers**: a Go interface normalizing heterogeneous input into a common `Signal`. v1
  ships Trivy `VulnerabilityReport` CRs only. A generic webhook *receiver* (as opposed to
  `internal/notify`'s outbound sink, which already exists) is slice 10, not v1 - this bullet
  previously claimed it shipped with v1; it didn't, corrected 2026-09-24. Falco, SonarQube,
  Alertmanager, etc. slot in behind that receiver once it exists, without a bespoke CRD-watching
  provider each - none of them expose a Kubernetes CRD the way Trivy Operator does, but all of them
  can already POST a webhook on their own (SonarQube on analysis completion, Falco via
  falcosidekick), so one receiver unlocks several tools at once.
- **Fingerprint + budget layer**: sits between signals and the model. The load-bearing
  differentiator — nothing reaches the LLM without passing through it.
- **LLM abstraction**: pluggable interface. Anthropic is the v1 implementation (structured output,
  one env var, no local-model setup friction). Ollama is next (slice 10), not OpenAI - the reason
  is adoption, not novelty: a mandatory hosted-API dependency and its per-call spend is real
  friction for the self-hosted, cost-sensitive, sometimes air-gapped shops this project targets,
  and Ollama removes both. OpenAI remains a plausible third implementation, just not the one that
  answers a real blocker.
- **Action catalog**: fixed and enumerated. v1 ships `Notify` and `ProposePullRequest`.
  `IsolateServiceTraffic` (the kept quarantine idea) lands only once the verification loop is
  demonstrably working — it's the highest-risk action and earns its place last.
- **CRDs**: `SignalPolicy` (scope, providers, guardrails, mode, budget), `Finding` (one per
  fingerprint; ranked hypotheses, confidence, verification outcome), `Suppression`.
- **API group**: `candor.dev/v1alpha1`.
- **GitOps backend**: `internal/gitops.Opener` is already an interface with one implementation
  (`GitHubOpener`). GitLab is slice 11 - a second implementation behind the same interface, not a
  core change.

## Every accelerator ships with its brake

**Non-negotiable, and it governs every slice below.** Any mechanism that can act, spend, or
generate must have its limit defined and enforced in the *same change* that introduces it. Not the
next slice, not "before v1". The same pull request.

A brake added later is not a brake, because the window in which it was missing is exactly the
window in which the thing runs unattended and nobody is watching for a failure mode that has not
been imagined yet. The worst shape is the self-multiplying one: an action that produces a signal
that triggers the same action.

What counts as a brake:

- A hard ceiling with a defined window (`Budget.maxCalls`), and a defined behaviour on hitting it
  that **degrades rather than fails**.
- A gate that makes repeat work a no-op (`NeedsEnrichment`, keyed on content, not time).
- A kill switch a human can reach without a rebuild, and which is visible in status and Events.
- A test that proves the limit actually holds against real volume, not that the accounting is
  internally consistent. `TestFindingReconciler_BudgetCostRegression` is the pattern: N genuinely
  distinct items against a ceiling of 2, asserting exactly 2 calls happen.

**Where this stands today.** Slice 9 shipped (below), so the *action* path now has brakes too, not
just the *cost* path (fingerprint gate, budget ceiling, suppression). `ProposePullRequest` is
gated by a per-namespace budget (`internal/signal.CheckPullRequestBudget`), a cluster-wide budget
that fails *closed* rather than open when no `OperatingPolicy` exists
(`internal/signal.CheckGlobalPullRequestBudget`), and a panic switch checked before either budget
is touched (`internal/signal.InAuditMode`) - all three proven under real volume by
`TestFindingReconciler_ProposePullRequestCostRegression` and
`TestFindingReconciler_ProposePullRequest_PanicSwitchMidRun_StopsSubsequentAttempts`. The
`IsolateServiceTraffic` quarantine action and Enforcing mode remain design intent, not implemented
code, as of this writing (2026-09-24) - see slice 9's own delivery note below for what did and
didn't ship with it.

**This binds slice 9 specifically.** `ProposePullRequest` is the first mechanism that writes
anything outward. It does not ship without, in the same slice:

- a cap on pull requests opened per window, per namespace, that degrades to Notify on exhaustion
- a global rate limit across all namespaces, so one noisy provider cannot exhaust the whole cluster's
  allowance
- a panic switch that drops to Audit mode and is reachable by editing a CRD, not by redeploying
- a test that proves each of those holds under volume

The same rule applies to anything that generates artifacts to reduce noise. A mechanism that
answers "too much to deal with" by producing more things to deal with has to justify its output
budget explicitly, or it is not a solution.

## Delivery slices

1. Repo prep, kubebuilder scaffold, CI, OSS boilerplate, release automation (goreleaser, cosign +
   SBOM + buildx provenance on the image, Helm chart published to GHCR), repo governance
   (branch protection, required signed commits, Dependabot + auto-merge, OpenSSF Scorecard,
   GOVERNANCE.md). **Done.**
2. `SignalPolicy` + `Finding` CRDs; Trivy provider; no LLM yet — deterministic findings only.
   **Done.** Identity between reconciles is currently the signal's source (provider + originating
   object), not real content-addressed fingerprinting — that's slice 3's job. Provider skips
   registering itself if the target CRD isn't installed, rather than crashing the manager.
3. Fingerprinting + cache + the cost regression test. **Done**, scoped honestly to what's provable
   without an LLM to gate yet: `Finding.status.fingerprint` (content hash) and `.enrichedFingerprint`
   (what was last enriched) exist and are wired through `Ingest`; `NeedsEnrichment` is the gate
   slice 4's real LLM call plugs into unchanged. No separate cache store - the Finding object's own
   status field *is* the cache, so there's no new storage to add. The cost regression test proves
   `NeedsEnrichment` makes exactly one true→false transition across N ingests of identical content,
   and reverses only when content actually changes - it can't yet prove "one LLM call" literally,
   since none exists; that's slice 4's own test, trivial once this mechanism exists to sit on.
4. LLM enrichment (Anthropic) behind the interface; ranked hypotheses with confidence. **Done.**
   `internal/llm.Client` is the interface; `internal/llm/anthropic` is the only implementation so
   far. Uses Anthropic's structured outputs (grammar-constrained JSON, GA as of late 2025) rather
   than the older tool-use-emulation workaround, verified against the real, current API request
   shape before building against it. `FindingReconciler` is the gate: `NeedsEnrichment` (slice 3)
   decides whether to call at all, so the cost regression test from slice 3 is now literal - it
   counts real (fake, interface-real) LLM calls across N reconciles, not just fingerprint
   transitions. `ANTHROPIC_API_KEY` unset is a fully supported configuration (deterministic
   findings only), not an error, matching the "provider not installed" stance from slice 2.
5. Budget ceiling + degraded mode + self-metrics + K8s Events. **Done.** `SignalPolicy.spec.budget`
   (`maxCalls`, `windowSeconds`, default 24h window) is optional - omitted means unlimited, relying
   entirely on the slice 3/4 fingerprint gate to bound cost. `internal/signal.CheckBudget` tracks
   usage on `SignalPolicy.status` (`budgetWindowStart`, `budgetCallsUsed`), resets on window expiry,
   and sets a `BudgetExhausted` condition. On exhaustion, `FindingReconciler` skips the LLM call
   (degrading to deterministic-only findings, not erroring) and emits a Warning Event on the
   `SignalPolicy` so degradation is visible without polling status. Four Prometheus counters/gauges
   (`internal/metrics`) expose calls made, calls skipped by reason, and budget used vs. limit per
   policy - proven with real registered-metric assertions (`testutil.ToFloat64`), not just "the code
   compiles". `TestFindingReconciler_BudgetCostRegression` proves a budget of 2 caps real LLM calls
   to exactly 2 across 5 genuinely distinct Findings - the literal ceiling claim, enforced by test.
6. `Suppression` CRD. **Done.** `Suppression.spec` is `fingerprint` (required - the exact
   `Finding.status.fingerprint` value to mute), `reason` (required - suppression is never silent),
   and optional `expiresAt`. Matching is exact by construction: `internal/signal.FindActiveSuppression`
   matches on the literal fingerprint string, so if the underlying signal's content genuinely
   changes, its fingerprint changes too, no longer matches, and the Finding resurfaces on its own -
   there's no separate "resolved" state to fall out of sync. `FindingReconciler` checks for an
   active Suppression before the LLM gate (so it applies even with no LLM configured - suppression
   is about noise, not just cost), sets a `Suppressed` condition, and skips enrichment while active.
   It watches `Suppression` objects directly (not just `Finding`), so creating, editing, or deleting
   one re-evaluates every Finding it could affect immediately, rather than waiting for some
   unrelated event to touch them. `SuppressionReconciler` maintains its own `Expired` condition
   (requeued exactly at `expiresAt`) purely so `kubectl get suppressions` shows a lapsed one at a
   glance. Also fixed in passing: `no_llm_configured` was documented in the
   `candor_enrichment_skipped_total` metric's help text since slice 5 but never actually
   incremented - it is now.
7. Verification loop + published accuracy metrics + Grafana dashboard in the chart. **Done.**
   `Finding.status.verificationOutcome` (StillPresent/Resolved/Recurred - three of the design doc's
   four states; "Superseded" is deliberately not implemented, since it would need multiple
   providers reporting conflicting signals about the same Finding, which doesn't happen yet) is
   written by `internal/signal.Ingest` on every reconcile of the Finding's source, not asserted
   once at creation. The gap this closes: previously, a Trivy `VulnerabilityReport` whose
   vulnerabilities got fixed (or dropped below every `SignalPolicy`'s threshold) left its Finding
   showing stale severity forever - `translate()` now produces a Signal even for a clean report
   (with an empty Severity that `signal.AtLeast` guarantees never clears any real threshold), so
   `Ingest`'s existing filtered path can recognise it and resolve the Finding instead of just
   discarding the signal. `candor_verification_transitions_total` (by outcome) is the published
   accuracy signal - the resolved:recurred ratio over time is an honest, provable "did this
   actually get fixed", not a calibrated ML accuracy score against a fixture suite (that's a
   distinct, separately-deferred piece of future work, not something this slice claims). A Grafana
   dashboard (`charts/chart/files/grafana-dashboard.json`, shipped as a ConfigMap gated by
   `grafanaDashboard.enabled`, labelled for the kube-prometheus-stack sidecar to auto-discover)
   plots LLM calls, enrichment skipped by reason, verification transitions, budget usage, and the
   cost-avoidance ratio - the dashboard is the proof surface docs/design.md's interaction-surfaces
   section calls for, not decoration. Also discovered and documented: a custom top-level
   `values.yaml` key doesn't survive `kubebuilder edit --force` (the whole file is regenerated from
   the plugin's own template, not merged) - a fourth recurring hand-fix, added to CONTRIBUTING.md
   alongside the original three. Tested for real, not just "the JSON parses": CI imports the
   dashboard into a real Grafana instance and checks every panel round-trips (structural, not full
   schema validation - Grafana's save API doesn't reject a bad panel type or query), and
   `hack/grafana-preview/` is a local `docker compose` stack (fake metrics + Prometheus + Grafana,
   both auto-provisioned) for a human visual check without a real cluster.

   Redesigned after review: the original layout led with Candor's own cost/self-observability
   metrics, which reads as "look how efficient we are" rather than answering the question an
   operator actually opens the dashboard for - what needs attention, right now. Fixing that
   exposed a real gap: none of the existing metrics represent a live current count of Findings by
   severity, only transition counters. Added `candor_findings_current{namespace,severity,outcome}`
   as a Prometheus `Collector` (`internal/metrics.FindingsCollector`) - computed fresh from the
   manager's cached client on every scrape, the same reasoning kube-state-metrics is built on,
   since a plain counter can't correctly express "how many are open right now" (transitions don't
   net out to a current count). `candor_verification_transitions_total` also gained a `severity`
   label (previously `outcome` only) - refined several times more after review. Each severity
   tile shows three values together (Outstanding, Resolved (7d), Recurred (7d)) rather than a
   separate panel per concept, since an operator wants one place per severity to answer "does this
   need action or is it handled" - "Recurred", not "Recurring", to match the past-tense,
   discrete-event framing of "Resolved" and the underlying `VerificationRecurred` constant, not an
   ongoing state. Laid out as four tiles side by side (one per severity), each internally split
   into three stacked horizontal bands - not a single multi-value stat panel, since Grafana's own
   "vertical orientation" setting did not reliably stack multiple values the way its documentation
   describes; explicit per-value panels positioned via grid coordinates give deterministic control
   instead of relying on that. Also fixed two real bugs caught in review: the multi-value stat
   panels were issuing range queries while asking to display every returned value, rendering as a
   wall of one box per timestamp sample instead of one current number (fixed with `instant: true`
   on every such target); and `Resolved`/`Recurred` counts wrapped in `floor()`, not left to round
   naturally, since `increase()` over a partial window can extrapolate a fractional value and
   rounding up would claim an event happened that isn't actually confirmed. The original drill-down
   panels remain, grouped under labelled rows.
8. Generic webhook sink + periodic digest report. **Done.** `SignalPolicy.spec.webhook.url`
   (optional) is the single opt-in for both: `internal/notify` is a small, vendor-agnostic package
   that POSTs a JSON payload and knows nothing about Slack/Teams/PagerDuty - "one code path", per
   the design. `internal/signal.Ingest` sends an immediate `Event` notification (FindingCreated,
   FindingResolved, FindingRecurred) on real transitions only - not on a routine content refresh or
   an unchanged reconcile, which would just be noise. `internal/controller.DigestRunnable` is a
   plain manager `Runnable` (a ticker loop, not a CRD-triggered reconciler - there's no event for
   "time has passed") that, on `CANDOR_DIGEST_INTERVAL` (default 24h), lists every SignalPolicy
   with a Webhook configured and sends a per-namespace `Digest` tallying Findings by verification
   outcome and severity - the "AIOps: Prove It!" artifact the evidence base calls for. Both send
   paths are best-effort: a failure is logged and counted (`candor_webhook_sends_total`), never
   returned as an error - a flaky notification endpoint must not make Finding reconciliation or
   the digest loop get stuck.
9. `ProposePullRequest` action against the GitOps repo. **Done.** Fires only when a fix is
   independently, mechanically verifiable - a Trivy `VulnerabilityReport` where every vulnerability
   agrees on one `fixedVersion` (`internal/gitops.ComputeFix`) - regardless of what the LLM
   recommends; no such fix, no PR. Branch/commit/PR creation is idempotent
   (`internal/gitops.GitHubOpener`, treats GitHub's "already exists" as success, not an error).
   Shipped with all three brakes this rule requires in the same change: a per-namespace cap that
   degrades to `Notify` on exhaustion, a cluster-wide cap via the new cluster-scoped
   `OperatingPolicy` CRD that - unlike every other budget in Candor - fails *closed* when no
   `OperatingPolicy` exists (there's nowhere to persist a count, so allowing anyway would be an
   uncounted, unenforced brake), and a panic switch (`OperatingPolicy.spec.mode: Audit`) checked
   before either budget is touched, reachable by editing a CRD with no redeploy. Order matters and
   is enforced: the GitHub token Secret is validated before either budget is consumed, so a
   misconfigured Secret can never burn budget for a PR that was never going to open. The controller
   gains no cluster-wide Secret access for this - a namespace enabling it grants a namespaced Role
   naming the one Secret explicitly (Trivy's config scan, KSV-0041, caught the cluster-wide version
   of this before merge). Released as `v0.1.0`, the first tagged release.
10. Generic webhook signal receiver + Ollama LLM backend. **Done.** Revised 2026-09-24 from "second
    provider (webhook ingest) + second LLM backend - proves both interfaces actually abstract" to
    name the actual motivation: adoption, not abstraction-proving for its own sake. The mandatory
    hosted-API dependency (`ANTHROPIC_API_KEY`, real per-call spend) is genuine friction for the
    self-hosted, cost-sensitive, sometimes air-gapped shops this project targets - Ollama removes
    it (`internal/llm/ollama`, issues #52/#53). The webhook receiver
    (`internal/provider/webhook`, issues #50/#51) is the cheaper way to add SonarQube, Falco, and
    similar tools: none exposes a Kubernetes CRD the way Trivy Operator does, but all of them can
    already POST on their own, so one receiver unlocks several tools instead of a bespoke
    CRD-watching provider per tool. Ships with its own brake: `SignalPolicy.spec.webhookReceiver`
    is required, not optional-with-a-default - the one guardrail in Candor with no conservative
    fallback, since an unauthenticated receiver that can create Findings is a spoofing vector, not
    a lesser version of the feature. Every request is HMAC-signed and constant-time-compared
    against a per-namespace Secret, same namespaced-Role opt-in as `GitOpsRepo.SecretRef` (no
    cluster-wide Secret access, ever). A webhook-sourced Finding has no owner reference - unlike a
    CRD-backed provider, there's no persistent Kubernetes object behind the delivery to own it, so
    it won't be garbage-collected the way a Trivy-sourced Finding is when its source is deleted, a
    real and documented consequence of accepting external signals, not an oversight.

    **A real, significant bug was found and fixed only because this shipped with genuine
    real-cluster verification, not fake-client or envtest unit tests alone.** `ctrl.NewManager`'s
    default client caches every type it reads via List+Watch informers. Since the ServiceAccount
    deliberately has no cluster-wide list/watch on Secrets (KSV-0041), a cached `Get` on a named
    Secret blocked forever - the reflector logged `secrets is forbidden ... at the cluster scope`
    and retried indefinitely, hanging every caller silently, with no timeout and no error. This
    affected the webhook receiver's Secret read *and* the pre-existing `GitOpsRepo.SecretRef` read
    from slice 9 - the same latent bug had shipped undetected since then, because fake clients
    don't simulate caching or RBAC, and envtest's default client bypasses RBAC entirely. Fixed via
    `Client.Cache.DisableFor` on the manager (`cmd/main.go`), verified against a live Kind cluster:
    before the fix, a real signed webhook request timed out completely; after, it returned 202 and
    created a Finding correctly. Automated coverage for this specific class of bug was tracked
    separately (#58) rather than bundled here, since it needed RBAC-scoped test infrastructure the
    suite at the time didn't have - since landed: `cmd/main_test.go` impersonates a real
    RBAC-restricted identity against a real envtest control plane (`rest.ImpersonationConfig`, not
    a fake client or the suite's own admin config) and proves the exact configuration `cmd/main.go`
    ships either succeeds or reproduces the original hang, depending on whether `Client.Cache.
    DisableFor` is set. Disabling the cache also turned every request's Secret `Get` into an
    uncached, direct apiserver round trip - including ones that fail signature verification
    regardless, since the Secret has to be read before a signature can be checked. Tracked
    separately (#60) as a DoS-hardening gap rather than blocking this PR on it, and since landed: a
    20s in-process, TTL-invalidated cache of resolved HMAC keys (not watch-invalidated - a watch
    would need back the exact cluster-wide Secret permission disabling the cache was meant to avoid
    needing). A misconfigured or missing Secret is deliberately never cached, so fixing it takes
    effect on the next request rather than waiting out the TTL.

    **A single `/code-review high` pass before opening the PR found five more real issues, none
    caught by the test suite that existed at that point** (candor's own new `CLAUDE.md`, written
    the same day): the receiver was gated behind leader election so a non-leader replica in a
    multi-replica deployment never started it at all; no Service or container port actually
    exposed port 9444, so the feature compiled and unit-tested clean while being unreachable via
    any standard `make deploy`/`helm install`; a signal authenticated against one `SignalPolicy`'s
    secret could be accepted or routed by a different, laxer policy in the same namespace, since
    `Ingest`'s namespace-wide acceptance semantics (correct for Trivy) didn't account for a
    provider where authentication binds to one specific policy; a `SignalPolicy` enabling
    `webhook` without configuring `webhookReceiver` reported `Ready: True` despite the receiver
    failing closed for it; and an oversized body was silently truncated before signature
    verification, surfacing as a misleading 401 instead of a clear size-limit error. All five
    fixed, each with a regression test, and the leader-election and Service fixes re-verified
    against a real 2-replica cluster deployment specifically because neither is something a unit
    test can observe. **A second `/code-review high` pass, run again per the same `CLAUDE.md` rule
    ("re-run after fixing what it finds, not just once"), found six more**: a `Start` error would
    have crashed the whole manager rather than just the receiver (controller-runtime shares one
    error channel across every Runnable); no `ReadTimeout` left the receiver open to a
    slowloris-shaped stall; a policy wrong in two ways at once only ever reported the first; a
    wasteful re-List where a targeted Get was already possible; a missing log line on one specific
    apiserver-Get failure path; and a hardcoded error-message string that could drift from the
    constants it was describing. All six fixed, two lower-severity findings deliberately deferred
    (#61, #62) with reasoning recorded on each issue rather than bundled in. A further
    lower-severity finding across these passes, deduplicating the Secret resolve-and-validate logic
    this receiver and `GitOpsRepo` each carried their own copy of, was also deferred (#59) and has
    since landed as `internal/signal.ResolveSecretKey`, used by both. **A third pass found
    the deepest one yet**: `RestrictToPolicy` correctly scoped *authentication*, but the resolve
    path still used that same narrowed view to decide whether an existing Finding should close -
    since `findingName` has no policy component, a Finding is namespace-wide, and a sibling
    policy's still-active interest in it must never be overridden by one request's narrower
    authorization scope. Also closed the redundant Get and the TOCTOU window between it and the
    original authenticating Get by having `RestrictToPolicy` carry the already-fetched object
    directly rather than just its name. **A fourth pass found the request-handling order itself
    was wrong**: reading the body only after two apiserver calls let apiserver latency eat into
    the same `http.Server` `ReadTimeout` budget the body read needed, since that timeout runs from
    request start regardless of when the handler gets around to reading - fixed by reading the
    body first. Also caught a test that never exercised the code path it claimed to (an
    auto-populated `Content-Length` meant it never reached the `io.LimitReader` logic), and a
    plugin-generated Helm Service template with no enablement guard, unlike the Deployment it
    fronts - a fifth regeneration gotcha now in `CONTRIBUTING.md`. **A fifth pass found the
    previous fix incomplete on both its own findings**: the body-read reordering moved the read,
    but not the handler's own timeout, which still started before it, defeating the point; and the
    `Start` fix from an earlier pass only covered the `ListenAndServe` error branch, leaving the
    graceful-shutdown branch still capable of propagating a fatal error to the whole manager the
    same way. **A sixth pass found the deepest identity bug yet**: `Provider` and `RefKind`'s
    sentinel were both fixed constants for every webhook delivery, so Finding identity collapsed to
    the sender-supplied `id` alone - two different tools behind two different policies picking
    overlapping ID schemes would have silently shared one Finding. `RefKind` now includes the
    authenticated policy's name. **A seventh pass found a real observability gap and a now-provable
    redundancy**: `Receiver.Start` never returning an error (necessary) meant a dead receiver was
    otherwise invisible - a new `candor_webhook_receiver_up` gauge is the alertable signal instead.
    It also proved the round-six `RefKind` scoping makes an earlier round's sibling-policy check
    unreachable for the only caller that sets it - kept anyway, since removing it would couple
    `Ingest`'s own correctness to one caller's current construction rather than standing on its own.
    **An eighth pass found the new gauge itself had a race**, no write/idle timeout hardening to
    match the read side, and that enabling the chart's existing `networkPolicy.enabled` toggle
    would have silently dropped every webhook request at the network layer - the one failure mode
    on this path that wouldn't have been observable. All three fixed; investigating the third
    surfaced a real, pre-existing, broader gap (`config/network-policy/` disconnected from
    `config/default` entirely, tracked separately as #64, not fixed here). `CHANGELOG.md` has the
    full list from all eight passes; not duplicated here.
11. GitLab GitOps backend. **Done.** `internal/gitops.Opener` gained a second implementation,
    `GitLabOpener`, dispatched alongside `GitHubOpener` by a new `MultiOpener` keyed on
    `GitOpsRepo.Provider` (a closed CRD enum, defaults to `github`). `GitOpsRepo.Host` lets either
    provider point at a self-hosted instance instead of the public SaaS API.

    Several `/code-review high` passes found real issues, tracking severity mostly down each round:
    a missing `gitlab.WithoutRetries()` meant a degraded GitLab instance could hold a call open for
    minutes instead of failing at `httpTimeout`, matching `GitHubOpener`'s own no-retry behavior;
    `GitHubOpener` never actually read the new `Host` field, so its own doc comment's GitHub
    Enterprise promise did nothing; a later pass found `Host` was then applied to `client.BaseURL`
    directly rather than through go-github's `WithEnterpriseURLs`, which is what actually appends
    the `/api/v3/` suffix Enterprise's API requires; `GitLabOpener` dereferenced a branch's commit ID
    with no nil check (GitLab's `CreateBranch` accepts a branch name directly as `Ref`, so the
    preceding `GetBranch` call - and the dereference - could be, and was, removed entirely); GitLab's
    `UpdateFile` was missing the `LastCommitID` optimistic-concurrency guard `GitHubOpener` already
    has via `content.SHA`; and the Helm chart's bundled CRD copy (`charts/chart/templates/crd/`)
    wasn't part of the regeneration this field's addition needed, silently pruning `provider`/`host`
    on any Helm-based install (fixed per CONTRIBUTING.md's chart regeneration checklist).
12. Fixture suite + published per-model accuracy. The evidence gap #7's answer already promises
    ("per-model accuracy is measured and published against a fixture suite, not asserted") and
    that Candor doesn't yet have. Required before any claim about a smaller or fine-tuned model's
    accuracy - see the deferred item below, which depends on this slice existing first. Once the
    Ollama backend (slice 10) exists, scope this to include candidate open models specifically, not
    only Anthropic model choices - "which open model, if any, is good enough" becomes an answerable
    question at that point, and should be answered by this suite, not by reputation or a vendor
    benchmark.
13. Blog article.

Quarantine/Enforcing mode is explicitly post-v1, gated on slice 7.

Deferred, deliberately not slice 1: SLSA provenance for the goreleaser-built binary archives (the
container image already gets buildx's native provenance attestation — the binaries would need the
official `slsa-framework/slsa-github-generator` reusable workflow, which is a real new job wired to
goreleaser's checksums, not a small extension of what already exists).

Deferred, deliberately not scoped as a slice: a fine-tuned or distilled model for the specific
tool set Candor targets (Trivy/SonarQube/Falco-shaped findings, ranking hypotheses, picking from
the fixed action catalog). The task is narrow enough that a small open model plausibly does it
well - much narrower than general chat - so this isn't dismissed as infeasible. But training one
before slice 12's fixture suite exists to measure it against would be exactly the kind of
unverified claim this project's whole thesis argues against: the right sequence is (a) Ollama
support (slice 10), (b) measure a good off-the-shelf open model against the hosted default on the
fixture suite, (c) only fine-tune if that measurement shows a real, published gap.

Grammar-constrained output for a locally-served model is real but conditional, verified 2026-09-24
against Ollama v0.34.3 (`llama3.2:3b`) before slice 10 implementation started, see issue #52's
comments for the raw evidence: passing a full JSON schema via the `format` field genuinely
constrains decoding - an enum held even under a direct prompt-injection attempt asking for an
out-of-catalog action. `format: "json"` alone does **not** - same injection prompt produced the
out-of-catalog value verbatim, since that mode only guarantees valid JSON, not schema conformance.
Only the full-schema form is a real constraint; `internal/llm/ollama` must never use the bare
`"json"` mode for anything that reaches the action catalog. The independent validation in slice
10's brake issue (#53) stays necessary regardless - this was one model, one test, defense in depth,
not proof it holds for every model.

Model provenance is a separate, real safety question for any locally-served model: recommend only
Ollama-registry models in GGUF format (flat tensor data), never an arbitrary third-party
`.bin`/`.pt` file - the older pickle-based PyTorch checkpoint format has real, documented
code-execution vulnerabilities via deserialization that GGUF does not share.

## Verification plan

- `envtest` reconciler tests: fingerprint stability (same state → same hash, changed state → new
  hash), budget exhaustion → degraded mode, suppression matching and expiry, verification outcome
  transitions.
- **Cost regression test**: N reconciles over unchanged state must produce exactly **one** LLM call.
  This is the project's core claim, and it's enforced by a test, not a README assertion.
- **Prompt-injection test**: a crafted malicious log line / image annotation must not alter the
  selected action.
- **RBAC test**: attempt a write with the operator's ServiceAccount; confirm denial.
- Deployed to the existing kind + ArgoCD cluster from `gitops-demo`; run against real
  dev/preprod/prod/pr-N namespaces. Every finding manually confirmed real — zero false positives —
  before any public write-up.
