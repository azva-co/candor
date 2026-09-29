# Candor

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/azva-co/candor/badge)](https://securityscorecards.dev/viewer/?uri=github.com/azva-co/candor)

A Kubernetes operator that ingests signals from security/observability tools (Trivy, and more
later), uses an LLM to enrich them into ranked hypotheses, and proposes remediation as GitOps pull
requests — with bounded LLM spend and a published record of its own accuracy.

📖 **[Full docs, architecture, and the case for Candor →](https://azva-co.github.io/candor/)**

**Status**: early build, shipped in slices — see [`docs/design.md`](docs/design.md) for exactly
what's done.

## Features

**What sets Candor apart:**

- **Bounded LLM cost, by construction** — an LLM call happens once per distinct cluster-state
  fingerprint, ever, not once per reconcile. A hard budget ceiling degrades to deterministic-only
  findings on exhaustion rather than silently spending past it.
- **GitOps-native remediation** — the default write path is a pull request against your GitOps
  repo, never a direct cluster mutation.
- **Published accuracy** — every finding is re-checked automatically, and its outcome (resolved,
  still present, recurred) is a queryable Prometheus metric, not a claim in a README.
- **Suppression that resurfaces on its own** — mute a fingerprint with a required reason and
  optional expiry; if the underlying content actually changes, it stops matching and comes back
  automatically. Nothing to remember to clean up.
- **Untrusted-input safe** — all ingested telemetry is treated as data, never instructions. Model
  output is grammar-constrained to a fixed action catalog; it can't emit a free-form action.
- **Every write path has a brake, not just the LLM** - a pull request only opens once the fix is
  independently, mechanically verified, and even then it's bounded by a per-namespace cap, a
  cluster-wide cap, and a panic switch that pauses it everywhere with no redeploy.

**What you'd expect from a tool in this space, done properly:**

- Provider-based signal ingestion (Trivy today; the interface is provider-agnostic)
- Fully Kubernetes-native — `kubectl get findings`, no separate UI or database to run
- Prometheus metrics and a ready-made Grafana dashboard, shipped in the Helm chart
- A generic webhook sink and periodic digest — one JSON payload shape, works with Slack, Teams,
  PagerDuty, or anything that can receive a POST
- Every release is signed, with a CycloneDX SBOM and build provenance attached

## Quickstart

```sh
helm install candor oci://ghcr.io/azva-co/charts/candor --version <version> \
  --namespace candor-system --create-namespace
```

Opt a namespace in:

```sh
kubectl apply -n <your-namespace> -f - <<EOF
apiVersion: candor.dev/v1alpha1
kind: SignalPolicy
metadata:
  name: default
spec:
  providers: [trivy]
  minSeverity: HIGH
EOF
```

If [Trivy Operator](https://github.com/aquasecurity/trivy-operator) is already scanning that
namespace, you'll see results as soon as it produces a `VulnerabilityReport`:

```sh
kubectl get findings -n <your-namespace>
```

That's it — deterministic findings work with zero further configuration. See
[Configuration](#configuration) below to enable LLM enrichment, a budget ceiling, suppression,
notifications, and GitOps pull request remediation.

## Configuration

LLM enrichment (ranked hypotheses on each `Finding`) is opt-in - without an API key it's simply not
active, not degraded:

```sh
kubectl create secret generic candor-llm --namespace candor-system \
  --from-literal=anthropic-api-key=<your key>
```

Uses [Anthropic's structured outputs](https://platform.claude.com/docs/en/build-with-claude/structured-outputs)
so enrichment output is grammar-constrained to the hypotheses schema - see
[`internal/llm/anthropic`](internal/llm/anthropic) and [`SECURITY.md`](SECURITY.md) for why that
matters given the input is untrusted scanner data. Override the model with
`CANDOR_LLM_MODEL` (default: `claude-sonnet-5`) via `manager.envOverrides` in the Helm chart's
values.

### Bounding the cost

```yaml
apiVersion: candor.dev/v1alpha1
kind: SignalPolicy
metadata:
  name: default
spec:
  providers: [trivy]
  minSeverity: HIGH
  budget:
    maxCalls: 50
    windowSeconds: 86400
```

On exhaustion, enrichment degrades to deterministic-only findings for the rest of the window.

### Suppressing a Finding

Mute a specific Finding by its exact content fingerprint:

```sh
kubectl get finding <name> -o jsonpath='{.status.fingerprint}'

kubectl apply -f - <<EOF
apiVersion: candor.dev/v1alpha1
kind: Suppression
metadata:
  name: known-false-positive
spec:
  fingerprint: "<the fingerprint above>"
  reason: "known false positive - tracked in TICKET-123"
  # expiresAt: "2026-12-31T00:00:00Z"   # omit for indefinite
EOF
```

Matching is exact by construction: if the underlying signal's content actually changes, its
fingerprint changes too, the Suppression no longer matches, and the Finding resurfaces on its own
- there's nothing to remember to delete or update.

### Webhook notifications and digests

Set `spec.webhook.url` on a `SignalPolicy` to get a JSON POST on every Finding created, resolved,
or recurred in that namespace, plus a periodic digest (`CANDOR_DIGEST_INTERVAL`, default `24h`)
tallying Findings by verification outcome and severity:

```yaml
apiVersion: candor.dev/v1alpha1
kind: SignalPolicy
metadata:
  name: team-a
spec:
  providers: [trivy]
  webhook:
    url: https://example.com/hooks/candor
```

It's a plain JSON POST with no vendor-specific formatting - point it at whatever turns JSON into a
Slack/Teams/PagerDuty message (a relay, a low-code webhook, etc.).

### Receiving signals from tools without a Kubernetes CRD

The inbound counterpart to the section above: Trivy works out of the box because it's CRD-shaped,
but SonarQube, Falco, and most other scanners aren't. Enable the generic receiver on a namespace's
`SignalPolicy`, and any tool that can POST an event on its own can feed Candor - no bespoke
provider needed.

```sh
kubectl create secret generic webhook-secret --namespace <your-namespace> \
  --from-literal=secret=<a random HMAC signing key>
```

```yaml
apiVersion: candor.dev/v1alpha1
kind: SignalPolicy
metadata:
  name: default
spec:
  providers: [webhook]
  webhookReceiver:
    secretRef:
      name: webhook-secret
```

POST Candor's own normalized envelope to
`http://candor-webhook-receiver-service.candor-system:9444/webhook/<namespace>/<signalpolicy-name>`
(the Service both the Helm chart and the kustomize base ship), signed with
`X-Candor-Signature: sha256=<hex-encoded HMAC-SHA256 of the raw body>`:

```sh
BODY='{"severity":"HIGH","kind":"Deployment","name":"api","summary":"SQL injection risk","id":"sonarqube-issue-123"}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "<the secret above>" | awk '{print "sha256="$NF}')

curl -X POST "http://candor-webhook-receiver-service.candor-system:9444/webhook/<your-namespace>/default" \
  -H "X-Candor-Signature: $SIG" -d "$BODY"
```

`id` is the sender's own stable identifier for the underlying issue (a SonarQube issue key, a Falco
rule+resource combination) - repeated deliveries with the same `id` update one Finding rather than
create a new one each time, the same identity guarantee every other provider gets for free from its
own CRD. A tool whose native webhook payload doesn't already match this shape needs a small
transform in front - the same relay-in-front pattern the outbound sink above uses, just running the
other direction.

No `webhookReceiver` configured means that namespace's endpoint always rejects, regardless of what's
posted to it - unlike every other guardrail in Candor, there's no conservative default here to fall
back to. The controller needs the same namespaced-Role opt-in as `gitOpsRepo` below to read the
Secret - no cluster-wide Secret access, ever.

### Proposing GitOps pull requests

Candor's default write path is a pull request against your GitOps repo, never a direct cluster
mutation. It only fires when a fix is independently, mechanically verifiable - today that means a
Trivy `VulnerabilityReport` where every vulnerability agrees on one `fixedVersion` - regardless of
what the LLM recommends. No such fix, no PR.

GitHub and GitLab (SaaS or self-hosted) are both supported - set `gitOpsRepo.provider` to pick one
(defaults to `github`) and `gitOpsRepo.host` if it's a self-hosted GitLab or a GitHub Enterprise
instance rather than the public SaaS API.

The controller deliberately has no cluster-wide access to Secrets, so enabling this needs two
things in the namespace: a token for the chosen provider, and a Role granting the controller's
ServiceAccount `get` on that one Secret specifically.

```sh
kubectl create secret generic github-token --namespace <your-namespace> \
  --from-literal=token=<a GitHub token with contents + pull-request write access>

kubectl apply -n <your-namespace> -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: candor-read-github-token
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["github-token"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: candor-read-github-token
subjects:
  - kind: ServiceAccount
    name: candor-controller-manager    # matches your Helm release name + "-controller-manager"
    namespace: candor-system
roleRef:
  kind: Role
  name: candor-read-github-token
  apiGroup: rbac.authorization.k8s.io
EOF
```

Then point a `SignalPolicy` at the repo to patch:

```yaml
apiVersion: candor.dev/v1alpha1
kind: SignalPolicy
metadata:
  name: default
spec:
  providers: [trivy]
  gitOpsRepo:
    provider: github                # optional, defaults to github - set to "gitlab" for GitLab
    # host: https://ghe.example.com # optional - self-hosted GitHub Enterprise or GitLab only
    owner: your-org
    repo: gitops-demo
    baseBranch: main               # optional, defaults to main
    path: apps/api/values.yaml
    yamlPath: image.tag
    secretRef:
      name: github-token
  pullRequestBudget:                # optional - omitting it still applies a conservative
    maxPullRequests: 5              # built-in default (1/24h), never "unlimited"
    windowSeconds: 86400
```

For GitLab, `owner` is the namespace the project lives in (a group, or `group/subgroup` for one
nested in a subgroup), `repo` is the project name, and `secretRef` should point at a personal or
project access token with `api` scope rather than a GitHub token - the RBAC and Secret-creation
steps above are otherwise identical, just naming a GitLab token instead.

The opened PR (or, for GitLab, merge request) carries the finding, its ranked hypotheses, and
confidence in the description - no new surface to learn beyond reading a normal PR/MR.

### The cluster-wide panic switch and rate limit

`SignalPolicy.spec.pullRequestBudget` bounds one namespace. `OperatingPolicy` - Candor's one
cluster-scoped resource - bounds the whole cluster, independently and in addition: a namespace
comfortably under its own budget can still be refused once the cluster-wide ceiling is spent by
everyone else combined.

It's also the panic switch. Flip `mode` to `Audit` to stop every `ProposePullRequest` action across
every namespace immediately, with no redeploy - checked before any budget is even touched, so it's
a genuine full stop, not "still counted but not executed."

```yaml
apiVersion: candor.dev/v1alpha1
kind: OperatingPolicy
metadata:
  name: default   # exactly one is meaningful cluster-wide; a second is flagged, not merged
spec:
  pullRequestRateLimit:
    maxPullRequests: 5
    windowSeconds: 86400
  mode: Active   # set to "Audit" to pause ProposePullRequest cluster-wide
```

Unlike every other budget in Candor, no `OperatingPolicy` existing at all means `ProposePullRequest`
is off cluster-wide, not "unlimited" - there's nowhere to persist a count, so allowing anyway would
just be an uncounted, unenforced brake. Create even an empty one to turn the action path on at the
conservative built-in default.

### Grafana dashboard

Ship a pre-built dashboard (LLM calls, enrichment skipped by reason, verification transitions,
budget usage, cost-avoidance ratio) as a ConfigMap the kube-prometheus-stack Grafana sidecar
auto-discovers:

```sh
helm upgrade --install candor oci://ghcr.io/azva-co/charts/candor \
  --set prometheus.enabled=true --set grafanaDashboard.enabled=true
```

## Installing without Helm

Each [release](https://github.com/azva-co/candor/releases) attaches a versioned `install.yaml`
(all resources, generated fresh at release time — not a stale copy on `main`):

```sh
kubectl apply -f https://github.com/azva-co/candor/releases/download/<tag>/install.yaml
```

Both install paths are produced by the same release pipeline — nothing hand-built or committed to
`main`, so what you install is always a specific, versioned, signed release. One content
difference: NetworkPolicy support is currently Helm-only (`--set networkPolicy.enabled=true`), since
`config/network-policy/` isn't wired into `config/default/kustomization.yaml` yet (tracked as
[#64](https://github.com/azva-co/candor/issues/64)), so a `kubectl apply -f install.yaml` install
gets no NetworkPolicy at all.

## Building from source (contributors)

### Prerequisites

- go version v1.24.6+
- docker version 17.03+
- kubectl version v1.11.3+
- Access to a Kubernetes v1.11.3+ cluster

### Quick local loop (Kind)

```sh
make dev-up      # creates (or reuses) a Kind cluster, builds the image, deploys Candor
make dev-status  # kubectl get pods -n candor-system
make dev-down    # tear the cluster down
```

`make dev-up` is safe to re-run after a code change - it rebuilds the image and redeploys onto the
same cluster. It also installs the pinned Trivy `VulnerabilityReport` CRD
(`test/crd/`), so you can hand-apply a `SignalPolicy` and a fake `VulnerabilityReport` and watch a
`Finding` come out the other end without a real Trivy Operator running. This is a separate,
persistent cluster from the one `make test-e2e` creates and destroys automatically around itself.

### Build, deploy, and run against a specific cluster or registry

```sh
make docker-build docker-push IMG=<some-registry>/candor:tag
make install                          # CRDs
make deploy IMG=<some-registry>/candor:tag
kubectl apply -k config/samples/      # sample SignalPolicy
```

> If you hit RBAC errors, make sure you're logged in with sufficient cluster privileges.

To tear back down:

```sh
kubectl delete -k config/samples/
make undeploy
make uninstall
```

The Helm chart source lives under `charts/chart/` (generated via `kubebuilder edit
--plugins=helm/v2-alpha --output-dir=charts`, regenerate the same way after changing the API or
RBAC). Published to the OCI registry on every tagged release, alongside the signed image.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — in particular the design constraints PRs must respect
(bounded LLM calls, read-only cluster access by default, no free-form model-selected actions).

**NOTE:** Run `make help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

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
