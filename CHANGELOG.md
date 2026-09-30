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

### Added

- Ollama LLM backend (`internal/llm/ollama`), a second implementation of `internal/llm.Client`
  alongside Anthropic - `CANDOR_LLM_PROVIDER=ollama` (default remains `anthropic`, unaffected),
  `CANDOR_OLLAMA_HOST` (default `http://localhost:11434`). Structured output uses a full JSON
  schema via Ollama's `format` field, verified (issue #52) to constrain the action enum even under
  a direct prompt-injection attempt - `format: "json"` alone does not and must never be used here.
- `hack/ollama-dev/`: a hardened local Ollama sandbox (digest-pinned image, non-root, read-only
  rootfs, capabilities dropped, loopback-only) for developing against the backend above.
- Generic webhook signal receiver (`internal/provider/webhook`), a new manager `Runnable` accepting
  inbound signals from tools without a Kubernetes CRD (SonarQube, Falco, etc.) via one normalized
  JSON envelope - `SignalPolicy.spec.webhookReceiver` opts a namespace in. Completes slice 10
  (`docs/design.md`) alongside the Ollama backend above.
- GitLab GitOps backend (`internal/gitops.GitLabOpener`), a second implementation of
  `internal/gitops.Opener` alongside GitHub, dispatched by a new `MultiOpener` keyed on the new
  `GitOpsRepo.provider` field (defaults to `github`). `GitOpsRepo.host` lets either provider point
  at a self-hosted instance instead of the public SaaS API. Completes slice 11 (`docs/design.md`).

### Fixed

- The manager's client no longer caches Secrets. Its default caching client tries to List+Watch
  every type it reads, but the ServiceAccount deliberately has no cluster-wide list/watch on
  Secrets (KSV-0041) - a cached `Get` on a named Secret blocked forever waiting for an informer
  sync that could never succeed, silently, with no timeout. Found via real-cluster verification of
  the webhook receiver below (issue #58 tracks adding automated coverage - fake clients and
  envtest's default admin config both structurally can't catch this, since neither enforces real
  RBAC). Also fixes the pre-existing `GitOpsRepo.SecretRef` read path, which had the same latent bug.
- The webhook receiver now runs on every manager replica, not only the leader
  (`Receiver.NeedLeaderElection() bool { return false }`) - without this, controller-runtime's
  default dispatch for a plain `Runnable` gates it behind leader election, so a non-leader replica
  in a multi-replica deployment never started the listener at all. Found via `/code-review high`
  against the installed controller-runtime source, confirmed by scaling to 2 replicas in a real
  cluster and checking both pods' listening sockets directly.
- The webhook receiver's Service and container port were both missing - the feature compiled,
  unit tests passed (they drive the handler directly, bypassing the network), and this file
  documented a working `curl` example, but nothing exposed port 9444 for any standard `make deploy`
  or `helm install` to actually reach. Added `webhook-receiver-service` (`config/default/`) and a
  `containerPort` entry; the README's example now uses the real Service name and was re-verified
  against a live cluster end to end.
- A signal authenticated against one `SignalPolicy`'s webhook secret could be accepted, or have its
  notification routed, by a different, laxer `SignalPolicy` in the same namespace -
  `internal/signal.Ingest`'s namespace-wide "any policy accepts" semantics (correct for Trivy, which
  has no per-object policy identity) didn't account for a provider where authentication *is* bound
  to one specific policy. New `Signal.RestrictToPolicy` narrows Ingest to exactly the authenticated
  policy when set.
- A `SignalPolicy` listing `webhookReceiver` provider without configuring `spec.webhookReceiver`
  reported `Ready: True`, contradicting the receiver's own fail-closed behavior for that exact
  policy (every request to it returns 404). Now reports `Ready: False` /
  `WebhookReceiverNotConfigured`.
- An oversized webhook request body was silently truncated to the 1 MiB limit before signature
  verification, so a legitimate request over the limit failed signature checking and surfaced as a
  misleading 401 rather than a clear "too large". Now rejected explicitly with 413.

- A `Receiver.Start` error (e.g. the port already in use) was returned directly, and
  controller-runtime propagates any non-nil `Runnable.Start` error into the manager's single
  shared error channel - terminating the whole process, not just the receiver, taking every
  unrelated reconciler down with it. Now logged and absorbed, matching
  `internal/controller.DigestRunnable`'s own convention in the same package (it never returns a
  non-nil error either).
- The receiver's `http.Server` set `ReadHeaderTimeout` but not `ReadTimeout`, so nothing bounded
  the time to read a request body - a client that sent headers promptly then trickled the body
  could hold a handler goroutine open indefinitely (slowloris-shaped), on exactly the component
  documented as needing the most hardening (the first inbound network surface from outside the
  cluster's own RBAC boundary).
- A `SignalPolicy` with both an unrecognised provider *and* a webhook misconfiguration only ever
  reported the first problem the reconciler's switch statement matched, hiding the second until
  the first was fixed and the policy reconciled again. Every applicable problem is now collected
  and reported together.
- `Ingest` re-listed every `SignalPolicy` in the namespace and discarded all but one on every
  signed webhook request, even though the receiver had already resolved the exact policy to
  authenticate the request in the first place. Now a targeted `Get` when `RestrictToPolicy` is set.
- The `SignalPolicy` Get error inside the receiver was silently folded into the generic 404
  response with no server-side log line, unlike the Secret Get and Ingest errors two lines either
  side of it - a transient apiserver problem was indistinguishable from a genuinely nonexistent
  policy. Now logged (except a genuine NotFound, which is routine, not an operational problem).
- The invalid-severity error message hardcoded its list of accepted values separately from the
  `signal.Severity*` constants the check itself uses, so the two could drift. Now built from the
  same constants the check switches on.

- A signal authenticated against one `SignalPolicy` but failing that policy's own threshold could
  incorrectly resolve a Finding that a different, still-active sibling policy in the same
  namespace would still accept - `findingName` has no policy component, so a Finding is shared
  namespace-wide, never owned by whichever policy happened to create it. Deciding whether to
  create/update a Finding stays restricted to the authenticated policy (the earlier fix above);
  deciding whether to *resolve* an existing one now always re-checks every policy in the namespace.
- `Signal.RestrictToPolicy` now carries the already-fetched `SignalPolicy` object instead of just
  its name, closing both a redundant apiserver `Get` (the webhook receiver had already fetched it
  once to authenticate the request) and a TOCTOU window between that authentication decision and
  Ingest's acceptance decision.
- The receiver's own request-handling timeout (10s) could already have expired by the time a
  legitimate slow upload finished reading its body (bounded separately by the server's 15s
  `ReadTimeout`), failing a merely-slow request as a hard error. **Superseded by a later pass
  below, not fixed this way**: sizing the two timeouts around each other turned out not to be
  enough (see the fourth pass's entry) - the actual fix reorders the body read ahead of the
  apiserver calls entirely, removing the race rather than budgeting around it.
- A `SignalPolicy` wrong in two independent ways at once (an unknown provider *and* a webhook
  misconfiguration) only ever reported the first one a switch statement matched. Every applicable
  problem is now collected and reported together; the two were also collapsed from parallel
  reason/message slices into one slice of paired values, closing an index-mismatch risk a future
  check could otherwise introduce silently.
- The receiver's success response was hand-built via string concatenation instead of
  `json.Marshal`, unlike every other JSON-producing call site in this codebase. An oversized
  request's `Content-Length` is now also rejected before either apiserver call the handler makes,
  not just after both plus the body read.

- The receiver read its request body only after two apiserver calls (SignalPolicy Get, Secret
  Get), but `http.Server`'s `ReadTimeout` is a connection-level deadline running from request
  start, not from whenever the handler gets around to reading the body - apiserver latency spent
  on those Gets first could exhaust the same budget the body read itself needed, failing a
  legitimate, promptly-sent small body under nothing worse than ordinary apiserver slowness. The
  body is now read first, before either apiserver call, so the two timeouts no longer compete.
- The regression test for the truncation fix above never actually exercised the code path it
  claimed to cover: it built its oversized body from a `*bytes.Reader`, which `httptest.NewRequest`
  auto-detects to populate `Content-Length`, so the request was rejected by the cheaper early
  `Content-Length` check before ever reaching the `io.LimitReader` logic that handles the case
  `Content-Length` actually being absent or wrong (chunked transfer encoding doesn't set it at
  all). Split into two tests, one for each path.
- The new webhook-receiver-Service Helm template had no enablement guard, unlike the Deployment it
  fronts - `helm template --set manager.enabled=false` still rendered it, with a selector matching
  no pods. This is a plugin-generated template (`charts/chart/templates/extras/`), not a
  hand-written custom one, so the guard would be silently dropped on the next chart regeneration
  without documenting it - added to `CONTRIBUTING.md`'s regeneration checklist as a new,
  previously-undiscovered gotcha.
- The sibling-policy check added earlier in this file ran unconditionally on every filtered
  webhook request, even when no Finding existed yet for it to protect. A cheap existence check now
  short-circuits before paying for the broader namespace list in the common case.
- A stray comment claimed a sibling `Runnable` lived in the same package as this one; it doesn't.
- The previous fix moved the body read ahead of the apiserver calls, but not the handler's own
  10s timeout, which still started at the top of the function - a legitimate upload taking most of
  the 15s read window could still exhaust the handler timeout before the apiserver calls it's
  meant to bound even began. The timeout is now created after the body read, not before.
- `Start`'s graceful-shutdown path still returned `srv.Shutdown`'s error directly, unlike the
  `ListenAndServe` error path a few lines below it - the exact "a Runnable error here is fatal to
  the whole manager" problem that path was rewritten to avoid was still reachable via the other
  branch (an in-flight slow-but-legitimate request extending past `Shutdown`'s 5s grace period
  during an ordinary rolling restart). Now logged and absorbed the same way.

- Provider (`"webhook"`) and the sentinel used for `RefKind` were both fixed constants for every
  delivery, so Finding identity collapsed to the sender-supplied `id` alone, with no per-policy or
  per-tool component. Two different tools behind two different `SignalPolicy` objects in the same
  namespace picking overlapping ID schemes (small sequential integers are a realistic example)
  would silently share one Finding, each overwriting the other's Spec and flipping
  `VerificationOutcome` for what looks like an unrelated finding from a different tool. `RefKind`
  now includes the authenticated policy's name.
- A transient apiserver error fetching the `SignalPolicy` (throttled, momentarily unreachable) was
  folded into the same 404 used for a genuinely nonexistent or unconfigured policy. A sender that
  retries on 5xx but not on 404 - a common convention - would drop the signal permanently on
  nothing worse than a backend hiccup. Now a distinct 500.
- The existence check ahead of the namespace-wide sibling-policy check, and the eventual resolve
  write, each did their own `Get` on the same Finding object. Merged into one fetch, reused for
  both.
- A `CHANGELOG` entry two entries above this one claimed the receiver's timeout and the server's
  read timeout "are now defined together so the handler timeout always exceeds the read timeout" -
  the actual shipped values are the opposite, since a later pass superseded that approach entirely
  in favour of reordering. Marked inline rather than quietly edited, matching this project's own
  citation-correction discipline elsewhere (`docs/design.md`'s "Origin and prior art" section).

- `Receiver.Start` deliberately never returns an error (a bind failure must not crash the whole
  manager), which meant a dead receiver was otherwise invisible - the manager's own healthz/readyz
  stay green regardless, and only a log line marked it. Added `candor_webhook_receiver_up`, 1 while
  running and 0 from the moment it stops for any reason - the thing to alert on instead of
  noticing Findings have stopped appearing.
- A namespace-wide sibling-policy check added earlier in this file (protecting a still-active
  policy's Finding from being resolved by a different, narrower-scoped request) is now provably
  redundant for the only caller that triggers it, since `RefKind` scoping by policy (also added
  earlier in this file) makes a cross-policy collision at that Finding's key structurally
  impossible. Kept anyway, documented as deliberate: removing it would couple `Ingest`'s
  correctness to one caller's current `RefKind` construction, which `Ingest` shouldn't need to
  assume to stay correct on its own.

- `WebhookReceiverUp` was set to 1 immediately after launching the listener goroutine, without
  confirming the bind itself had actually succeeded yet - a port already in use could report "up"
  for a moment (or longer, under scheduler contention) before the goroutine's own error landed,
  undermining the exact alerting guarantee the metric added two entries above this one exists for.
  Now binds synchronously (`net.Listen`, not `http.Server.ListenAndServe`) before the gauge is
  ever set, and handed off to `srv.Serve` only once that's confirmed.
- The receiver's `http.Server` set `ReadHeaderTimeout`/`ReadTimeout` but not `WriteTimeout` or
  `IdleTimeout`, leaving the same slowloris-class gap open on the write and idle-keepalive sides
  that the read side was explicitly hardened against. Both added.
- Enabling the chart's existing `networkPolicy.enabled` toggle - already documented, encouraged
  hardening - shipped a NetworkPolicy allowing metrics traffic but nothing for the new
  webhook-signal port. Kubernetes NetworkPolicy's default-deny-once-selected semantics meant every
  legitimate, correctly-signed webhook request would have been silently dropped at the network
  layer the moment anyone turned this on, with no log line from Candor itself to explain why - the
  one failure mode on this whole path that wouldn't have been observable. Added a second
  NetworkPolicy, deliberately open to any source rather than namespace-label-restricted like the
  metrics one: this receiver's real access control is the per-`SignalPolicy` HMAC signature, not
  network segmentation.

Thirty-six findings total came from eight `/code-review high` passes on this change before opening
its PR (candor's own new `CLAUDE.md`, "re-run after fixing what it finds, not just once. Stop once
a pass comes back clean, not before") - none were caught by the test suite that existed at the time
each pass ran. Seven lower-severity findings were deliberately deferred rather than bundled in
(#58, #59, #60, #61, #62, #63, #64 - filed as separate issues per this repo's own "issue before
architecture" rule). #58 (RBAC-scoped envtest coverage for the cached-Secret-read fix above), #59
(deduplicating the Secret resolve-and-validate logic `GitOpsRepo` and the webhook receiver each
had their own copy of), and #60 (a short-TTL cache bounding apiserver load from repeated Secret
reads on this now-uncached path) have since landed. #61 (provider-specific validation doesn't
generalize past this one instance yet), #62 (the receiver's port is hand-duplicated across
manifests the same way every other port in them already is, not a new inconsistency this change
introduced), #63 (`Ingest`'s synchronous outbound notification is pre-existing behavior shared with
the Trivy path, not something to fix inside this PR's scope), and #64 (`config/network-policy/` was
already disconnected from `config/default` before this change, so kustomize installs get no
NetworkPolicy regardless of the fix above - a pre-existing distribution-parity gap found while
fixing this, not introduced by it) remain open, each needing its own design decision rather than a
quick fix.

- `internal/signal.ResolveSecretKey` (#59): the single place that resolves a namespaced Secret by
  ref and validates a data key is present and non-empty, used by both `GitOpsRepo`'s pull-request
  path and the webhook receiver's HMAC-key path. They used to duplicate this logic, including the
  identical `"secret %s has no data key %q"` error string, with no single place to fix a bug in it
  for either path.
- Webhook receiver: resolved HMAC keys are now cached in-process for 20s
  (`hmacKeyCacheTTL`, #60). Disabling the manager's Secret cache (the fix above) turned every
  request's Secret `Get` into an uncached, direct apiserver round trip - including requests that
  fail signature verification regardless, since the Secret has to be read before a signature can
  be checked at all. TTL-based, not watch-invalidated: a watch would need back the same
  cluster-wide list/watch permission on Secrets that disabling the cache was meant to avoid
  needing. A misconfigured or missing Secret is never cached, so fixing it (creating or correcting
  the Secret) takes effect on the very next request rather than waiting out the TTL. Concurrent
  cache misses for the same Secret (a burst landing right after one TTL expiry) are coalesced into
  one resolve call via `singleflight`, not one apiserver `Get` per waiting goroutine - that shared
  call uses its own fixed `secretResolveTimeout` (5s), not any one participating request's own
  context. Deriving it from whichever request happens to become the singleflight leader was tried
  and rejected twice: tying it to the leader's own context let that one request's cancellation
  (client disconnect, its own deadline) fail every other request coalesced onto it despite their
  own contexts being healthy; tying it to the leader's own *remaining* budget instead (to avoid
  doubling this handler's worst-case latency) still made every coalesced request's outcome depend
  on a completely unrelated request's timeline - a follower with a fresh, generous budget could
  fail because it joined a leader whose own `SignalPolicy` Get had already eaten most of its
  budget. A fixed, independent timeout on the shared call avoids both: no participant's success
  depends on which other request happened to trigger it. A follower still respects only its own
  context's deadline while waiting, though - `DoChan`, not `Do`, so one waiter can give up on its
  own budget without affecting the shared call it's waiting on. And a cache entry is now swept on
  every `set`, not only lazily on a matching `get`, so a Secret that stops being queried entirely
  (a deleted/renamed `SignalPolicy`, a rotation under a new name) doesn't linger in memory for the
  life of the process. Five consecutive `/code-review high` passes on this cache found and fixed a
  real bug each before it shipped.

A further `/code-review high` pass on #59/#60 found one more gap, filed rather than folded in
since it's a different call path with its own design tradeoffs: `GitOpsRepo`'s Secret token lookup
goes through the same new `ResolveSecretKey` helper but has no equivalent cache, so it still
suffers the identical uncached-apiserver-round-trip regression, reachable indirectly through
Finding churn rather than directly through HTTP requests (#67).

- `internal/signal.Ingest`'s outbound `Spec.Webhook` notification no longer blocks `Ingest`'s
  return (#63) - it's queued onto a new shared, bounded pool (`internal/notify.SendAsync`) instead
  of sent inline. This mattered once the webhook signal receiver started calling `Ingest`
  synchronously from an HTTP handler: a slow or unreachable notification endpoint held up the
  response to whoever POSTed the original signal, for a side effect they never observe anyway.
  `internal/controller.DigestRunnable`'s per-tick digests share the same pool and get the identical
  fix - a slow policy's digest no longer delays every other policy's send in the same tick.

  The pool is a fixed 8 workers backed by a 256-slot queue; once full, a send is dropped and
  counted (`WebhookSendsTotal`'s new `dropped` result) rather than growing unbounded or blocking
  the caller. Both the send itself and the caller's own `done` callback run behind independent
  panic recovery on every path, including the queue-full one - these are long-lived background
  goroutines with none of the per-request/per-reconcile recovery every other code path here already
  gets, so an unrecovered panic anywhere in this pool would otherwise crash the whole
  controller-manager process for one dropped notification.

  Two accepted trade-offs: notifications about the same Finding sent close together (a rapid
  create-then-resolve) can now arrive out of order downstream, since they may land on different
  workers whose independent HTTP round trips finish in either order; and `Ingest`'s per-Finding
  notifications share one budget with `DigestRunnable`'s digests, so a handful of policies with
  slow/unreachable webhooks can, under a large enough simultaneous burst, cause unrelated
  notifications to be dropped rather than merely delayed.
- The webhook signal receiver's port (9444) is now templated through one Helm value
  (`manager.webhookReceiver.port`, resolved and validated by `candor.webhookReceiverPort` and
  `candor.validatedPort` in their own template file) instead of hand-duplicated across the
  container port, the Service, and the NetworkPolicy allow-rule - the same drift class already
  found once for this feature (a missing Service entirely). Setting it to `0` disables all three
  together, matching `cmd/main.go`'s own `signal-receiver-port > 0` flag semantics exactly
  (a negative value is treated as disabled too, not just `0`). Non-integer values, octal-looking
  leading zeros, and values too large for an `int` all fail chart rendering with a clear message
  instead of Sprig's own casts silently coercing them to `0` and disabling the feature with no
  warning; the same validator now also covers `manager.healthProbe.port` and `metrics.port`, the
  two ports this one is checked against for collisions, closing the same gap on their side of that
  check. Validation only runs when the port in question is actually used - skipped entirely under
  `manager.enabled=false` or `networkPolicy.enabled=false`, for instance - so a stale invalid value
  never blocks an unrelated deploy. The metrics Service/NetworkPolicy's own separate uses of
  `metrics.port` remain unvalidated, a pre-existing gap in files this change doesn't otherwise
  touch. The kustomize distribution's own literals are left hand-duplicated, matching every other
  port in that distribution - fixing that gap (e.g. via kustomize's `replacements`) is a separate,
  larger decision tracked loosely alongside #64's own kustomize/Helm parity gap.

### Security

- The webhook signal receiver above fails closed: no `webhookReceiver` configured means that
  namespace's endpoint always rejects. Every request is authenticated via a per-`SignalPolicy` HMAC
  shared secret (`X-Candor-Signature`, constant-time comparison) - unlike most guardrails in Candor,
  there is no conservative default that leaves this open.
- Independent, backend-agnostic validation of an LLM's recommended action
  (`internal/controller.sanitizeRecommendedAction`) before it reaches the CRD's own
  `+kubebuilder:validation:Enum` - previously an out-of-catalog value would have made the whole
  status update fail against the API server rather than being caught in application code first.
  Anthropic's own structured outputs made this unreachable in practice, but a less-constrained
  backend could reach it; this closes the gap for every backend, not just new ones.

- Release binaries (`checksums.txt`, covering every archive) are now keyless-signed with cosign,
  same identity as the container image. Previously only the image was signed.
- Bumped `cel-go` and `golang.org/x/mod` (both indirect) past disclosed vulnerabilities, and the
  `go` toolchain directive past a vulnerable range that CI was actually building with.

### Changed

- Dockerfile's builder image bumped to `golang:1.27.1`, pinned by digest alongside the runtime
  distroless base image.

### Dev tooling

- `lint.yml` deleted: it duplicated `ci.yml`'s own `lint` job (`make lint`) as a second, fully
  separate workflow, adding a whole extra billed job for the one line (`make lint-config`) it did
  that `ci.yml` didn't already do. That line is now a step in `ci.yml`'s existing `lint` job.
  `lint.yml`'s own job was never actually a required status check (its display name, "Run on
  Ubuntu", differs from `ci.yml`'s `lint` job, which branch protection does require) - deleting it
  doesn't touch what's required to merge. One real trade-off: `lint.yml` ran on every push to any
  branch, no branch filter; `ci.yml` only triggers on push/PR against `main`, so a branch pushed
  before a PR against `main` exists now gets no automated lint feedback until one is opened (once a
  PR exists, every subsequent push to it still re-triggers `ci.yml`'s own `pull_request` event, same
  as before). Accepted rather than widening `ci.yml`'s trigger to match, which would pull the whole
  matrix/e2e/grafana-dashboard jobs along with it - this repo's own practice is to open a PR
  immediately after pushing a branch, and `make lint` clean locally before every merge is already
  the stated primary gate (`CLAUDE.md`), not CI.
- `ci.yml`'s envtest matrix (`test (1.37)`/`test (1.31)`/`test (1.29)`) now only runs in full on
  push to `main` - a pull request only runs 1.37, the version `go.mod` actually targets; 1.31/1.29
  prove portability, which changes far less often than the code itself. Staged with a step-level
  `if:`, not a job-level one: `test (1.31)`/`test (1.29)` are required status checks by exact name,
  and a job whose steps are conditionally skipped still reports `success`, where a job-level skip
  risks a PR left waiting on a check GitHub never runs for that trigger at all.
- New `make ci` / `scripts/ci.sh`: runs `make build`/`test`/`lint`/`test-e2e` plus a Grafana
  dashboard-import check mirroring `ci.yml`'s own `grafana-dashboard` job, in one command, for
  local convenience (needs `docker`). Not solving a drift problem - every step calls a Makefile
  target CI itself already calls, so there's no separate copy of the logic to drift out of sync.

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
