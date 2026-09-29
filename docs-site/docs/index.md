---
title: Candor
description: A Kubernetes operator that treats LLM invocation as a metered, verifiable resource — not a stateless, unbounded one.
hide:
  - navigation
  - toc
---

# Candor

**A Kubernetes operator that ingests security signals, enriches them with an LLM under a hard
cost ceiling, and proposes fixes as GitOps pull requests — with a published record of its own
accuracy.**

[Why Candor](why-candor.md){ .md-button .md-button--primary }
[Get started](getting-started.md){ .md-button }
[View on GitHub :fontawesome-brands-github:](https://github.com/azva-co/candor){ .md-button }

---

## Built on three hard constraints

Ingesting a signal, asking an LLM what it means, and handing a human something actionable is a
well-established pattern in Kubernetes tooling by now. Candor's focus is on doing that job to a
standard: every LLM call is accounted for, every write respects GitOps, and every finding's
outcome is checked and published rather than asserted.

<div class="grid cards" markdown>

-   :material-currency-usd-off:{ .lg .middle } __Bounded cost, by construction__

    ---

    One LLM call per distinct cluster-state fingerprint, **ever** — not once per reconcile. A
    hard budget ceiling degrades to deterministic-only findings rather than silently spending
    past it, and a cost regression test enforces exactly that behaviour on every PR.

-   :material-source-pull:{ .lg .middle } __GitOps-native__

    ---

    The default write path is a pull request against your GitOps repo, not a cluster mutation —
    so it never fights Flux or Argo for control. *(Landing in the next milestone — see
    [status](#status).)*

-   :material-chart-line:{ .lg .middle } __Self-measuring__

    ---

    Every finding is re-checked, and its outcome — resolved, still present, or recurred — is
    published as a Prometheus metric and a Grafana dashboard shipped in the chart. Not a claim
    in a README: a number you can query.

</div>

## Publishing the number that earns trust

> "Data on how often your system produces useful, actionable results."
>
> — Majors & Hebert, SREcon25, [*AIOps: Prove It!*](https://www.usenix.org/conference/srecon25americas/presentation/majors)

60% of practitioners cite lack of trust as the top barrier to AIOps adoption; 59% require
near-perfect accuracy before they'll rely on it (The Register, 696 respondents). Candor's
accuracy metric — the resolved-vs-recurred ratio, tracked over time — is a direct answer to that:
a number you can query, shipped in v1 rather than left for later.

## Status

Candor is an early, actively-developed build, shipped in small, individually-verified slices —
each one tested against a real Kubernetes control plane, not mocked away. Deterministic
findings, content-addressed fingerprinting, LLM enrichment, a hard budget ceiling, Suppressions,
the verification loop, and a generic webhook sink are done. See
[the full delivery plan and rationale](https://github.com/azva-co/candor/blob/main/docs/design.md)
for exactly what's shipped and what isn't yet.

[Read the full case for Candor :material-arrow-right:](why-candor.md){ .md-button .md-button--primary }
