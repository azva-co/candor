# Contributing

Candor is early — architecture agreed, build in progress in slices (see the design doc). The most
useful contribution right now is discussion on an issue before a PR, since the CRD shapes and the
fingerprinting/budget model are still settling.

## Development

- Go (see `go.mod` for the minimum version).
- [kubebuilder](https://book.kubebuilder.io/) 4.x.
- `make test` (runs `envtest` against a real control plane — not mocked) and `make lint` before
  opening a PR. CI runs the same two via `ci.yml`, plus a k8s-version matrix and `make test-e2e`.
- `make dev-up` for a real cluster to poke at by hand - creates (or reuses) a persistent local
  Kind cluster, builds the image, and deploys Candor onto it. Safe to re-run after a code change
  (rebuilds and redeploys). `make dev-status` / `make dev-down` alongside it. Separate from the
  Kind cluster `make test-e2e` creates and destroys automatically around itself - this one stays
  up between runs.
- `make manifests generate` after editing any `_types.go` file, and commit the regenerated output.
- After a CRD or RBAC change, regenerate the Helm chart:
  `kubebuilder edit --plugins=helm/v2-alpha --output-dir=charts --force`. This **will** revert
  hand-maintained things back to their generated defaults — re-apply them every time:
  - `charts/chart/values.yaml`: `manager.image.repository` back to `ghcr.io/teerakarna/candor`,
    and `manager.webhookReceiver.port` (the plugin doesn't know this key at all, so it's dropped
    entirely, not reset to a default - re-add the whole `webhookReceiver: { port: 9444 }` block)
  - `charts/chart/.helmignore`: the `dist/chart/*.tgz` line back to `*.tgz`
  - `.github/workflows/test-chart.yml`: triggers back to `branches: [main]`, the
    `helm lint` path back to `./charts/chart`, **and its pinned action versions** - the plugin's
    own bundled template carries older `actions/checkout`/`actions/setup-go` SHAs than whatever
    Dependabot has since bumped them to. Discovered 2026-09-24 (slice 10's webhook receiver CRD
    field) when a regeneration silently rolled both back several versions - `git diff` the whole
    file after regenerating, not just the three items already listed here, since this plugin
    template can drift in ways beyond what's been caught so far.
  - Any other custom top-level key added to `values.yaml` by hand (e.g. `grafanaDashboard`) - the
    whole file is regenerated from the plugin's own template, so a key it doesn't already know
    about is silently dropped, not merged. A custom **template** file under `charts/chart/templates/`
    (and any file under `charts/chart/files/`) is untouched, since those aren't part of kustomize's
    output - only `values.yaml` itself gets wholesale regenerated.
  - Any Kubernetes `Service`/manifest added to `config/default/` (not part of the original
    scaffold, e.g. `webhook_receiver_service.yaml`) lands under `charts/chart/templates/extras/`
    once generated, and **is** wholesale-regenerated on every run - unlike the hand-written
    custom templates described above, this one *is* plugin-derived, so any manual guard added to
    it (e.g. `{{- if or (not (hasKey .Values.manager "enabled")) (.Values.manager.enabled) }}` to
    match the Deployment's own enablement condition) is silently dropped too. Discovered
    2026-09-25 (the same webhook receiver work): `helm template --set manager.enabled=false`
    still rendered the new Service with a selector matching no pods. Re-apply the guard and
    re-check with that same command after every regeneration. Its `port`/`targetPort` templating
    (`{{ include "candor.webhookReceiverPort" . }}`, not a bare literal) is dropped the same way -
    re-apply alongside the guard.
  - `charts/chart/templates/manager/manager.yaml` itself is also wholesale-regenerated (it's
    derived from `config/manager/manager.yaml`, not a template the plugin leaves alone) - every
    hand-added line needs re-applying: the `$whPort`/`$healthPort`/`$metricsPort` resolution block
    at the top of the `containers:` list, the two port-collision `fail` checks, the
    `--signal-receiver-port` arg, and the conditional `webhook-signal` `containerPort` entry.
    `charts/chart/templates/_webhookreceiver-helpers.tpl` (a plain custom file the plugin has
    never heard of, unlike `_helpers.tpl`) is untouched by regeneration and doesn't need
    re-applying - only its call sites in the regenerated files do.
  Verify with `helm lint charts/chart` and `helm template test charts/chart | grep image:` after.

## Design constraints that PRs must respect

These aren't style preferences — they're the project's whole reason to exist, each backed by a
documented failure in an incumbent tool. See the design doc's evidence base before proposing a
change that touches these:

- **No unbounded LLM calls.** Every enrichment call must go through the fingerprint + budget layer.
  A change that calls the model directly, bypassing fingerprinting, will be rejected regardless of
  how useful it seems locally.
- **Read-only cluster access by default.** The operator's ServiceAccount must not gain write RBAC
  outside the documented, gated Enforcing-mode path. `ProposePullRequest` (slice 9) doesn't violate
  this - its write lands in an external GitOps repo, never a cluster mutation.
- **No free-form model-selected actions.** Model output selects from the fixed action catalog; it
  never emits an action string that gets executed directly.
- **Every finding is falsifiable.** A new finding type needs a defined verification check — "how do
  we know this cleared" — before it ships.
- **No cluster-wide access to Secrets.** A namespace that needs the controller to read one (e.g.
  `SignalPolicy.spec.gitOpsRepo.secretRef`) grants a namespaced Role naming that Secret explicitly,
  never adding `secrets` to the operator's ClusterRole. Trivy's config scan (KSV-0041) caught this
  once already; it's a required CI check, not just a style preference.
- **A brake ships in the same PR as the accelerator it bounds, never after.** Any mechanism that
  writes, spends, or acts needs its limit - a cap, a kill switch, a test proving it holds under
  volume - defined and enforced in the same change (docs/design.md, "Every accelerator ships with
  its brake"). Slice 9 is the precedent: `ProposePullRequest`, its per-namespace and cluster-wide
  caps, its panic switch, and the volume test proving all three hold landed in one PR.

## Recording findings

Chat history is not a record, and a finding nobody wrote down did not happen. The test for where a
finding belongs is whether it survives the session somewhere durable.

| Situation | Where it goes |
|---|---|
| Fixed in the same change | No issue. The PR description and commit message are the record, and a better one, because they carry the fix and the evidence together |
| Found, but deferred | An issue, always. Otherwise it exists only in a conversation nobody will re-read |
| Found, won't fix, or the call belongs to someone else | An issue, for the same reason |
| Recurring, or it should shape future work | A design-doc section or constraint, not an issue |

Do not open an issue per observation. Answering "too much to keep track of" by producing more to
keep track of is the failure "Every accelerator ships with its brake" exists to prevent, and it
applies to the issue tracker as readily as to the code.

Include the measurement, not the impression. Two worked examples from this repo's own history: the
KubeGuard paper's F1 range was cited as 0.79-0.81 when the real range is 0.504-0.808, and the
citation for k8sgpt-operator#730 described a bug that had since been fixed. Both were caught by
re-checking against the live source, and both are recorded in `docs/design.md` with the correction
marked inline rather than quietly edited.

**Evidence decays.** Issues get fixed, projects ship the thing you said they never shipped, and
papers say something narrower than the summary of them. Anything cited publicly gets re-verified
first.

## Commit style

Conventional commits (`feat:`, `fix:`, `docs:`, `chore:`) where practical - enforced on the PR
title specifically (`pr-title-lint.yml`), since squash-merge makes that title the commit message on
`main`, which is what release-please reads.

## Releases

Versioning and `CHANGELOG.md` are handled by `release-please.yml`, not a person picking a number.
It maintains a standing PR that bumps the version and changelog from Conventional Commits since the
last release - merging that PR is the release, a deliberate choice rather than something automated
like `dependabot-automerge.yml`. It only pushes the resulting git tag; `release.yml`'s existing
goreleaser pipeline (binaries, cosign signing, SBOM, the actual GitHub Release) picks that up
unchanged, exactly as it did for a hand-pushed tag before.

## On how this project is built

This project is built collaboratively with Claude Code. That's disclosed here plainly, and it's
visible in the commit history regardless — the point isn't the disclosure itself, it's that a
project whose whole premise is refusing to assert what it can't back with evidence would be
undermining its own thesis if it weren't upfront about how it's made. Every technical claim in
[`docs/design.md`](docs/design.md) is sourced against a cited, checkable reference, not asserted.

## Reporting a security issue

See [SECURITY.md](SECURITY.md).

## Governance

See [GOVERNANCE.md](GOVERNANCE.md) for how decisions get made.
