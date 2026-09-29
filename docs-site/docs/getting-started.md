# Getting Started

## Install

```sh
helm install candor oci://ghcr.io/azva-co/charts/candor --version <version> \
  --namespace candor-system --create-namespace
```

Every release is signed and carries a CycloneDX SBOM and build provenance — see
[SECURITY.md](https://github.com/azva-co/candor/blob/main/SECURITY.md) for how to verify one.
A versioned YAML bundle is also attached to each
[release](https://github.com/azva-co/candor/releases) if you'd rather not use Helm.

Deterministic findings (Trivy `VulnerabilityReport` → `Finding`) work with zero configuration
beyond a `SignalPolicy`:

```yaml
apiVersion: candor.dev/v1alpha1
kind: SignalPolicy
metadata:
  name: team-a
spec:
  providers: [trivy]
  minSeverity: HIGH
```

## Enable LLM enrichment (optional)

Ranked hypotheses on each `Finding` are opt-in — without an API key, Candor produces
deterministic findings only, which is a fully supported configuration, not a degraded one:

```sh
kubectl create secret generic candor-llm --namespace candor-system \
  --from-literal=anthropic-api-key=<your key>
```

Override the model with `CANDOR_LLM_MODEL` (default `claude-sonnet-5`) via
`manager.envOverrides` in the chart's values.

## Bound the cost

```yaml
apiVersion: candor.dev/v1alpha1
kind: SignalPolicy
metadata:
  name: team-a
spec:
  providers: [trivy]
  minSeverity: HIGH
  budget:
    maxCalls: 50
    windowSeconds: 86400
```

On exhaustion, enrichment degrades to deterministic-only findings for the rest of the window —
never silently past the ceiling.

## Suppress a known false positive

```sh
kubectl get finding <name> -o jsonpath='{.status.fingerprint}'
```

```yaml
apiVersion: candor.dev/v1alpha1
kind: Suppression
metadata:
  name: known-false-positive
spec:
  fingerprint: "<the fingerprint above>"
  reason: "known false positive - tracked in TICKET-123"
  # expiresAt: "2026-12-31T00:00:00Z"   # omit for indefinite
```

Matching is exact by construction — if the underlying content actually changes, the fingerprint
changes with it, the Suppression no longer matches, and the Finding resurfaces on its own.

## Get notified

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

A plain JSON POST on every Finding created, resolved, or recurred, plus a periodic digest
(`CANDOR_DIGEST_INTERVAL`, default `24h`) — point it at whatever turns JSON into a Slack, Teams,
or PagerDuty message.

## See the accuracy dashboard

```sh
helm upgrade --install candor oci://ghcr.io/azva-co/charts/candor \
  --set prometheus.enabled=true --set grafanaDashboard.enabled=true
```

Ships a Grafana dashboard as a ConfigMap the kube-prometheus-stack sidecar auto-discovers: LLM
calls, enrichment skipped by reason, verification transitions, budget usage.

---

Full configuration reference, contribution guide, and design rationale live in the
[repository](https://github.com/azva-co/candor).
