# Security Policy

## Reporting a Vulnerability

Please report security issues privately using
[GitHub Security Advisories](https://github.com/azva-co/candor/security/advisories/new) for this
repository, rather than opening a public issue.

If you're unable to use Security Advisories, email 21040807+teerakarna@users.noreply.github.com
with a description of the issue and steps to reproduce.

Please do not disclose the issue publicly until it has been addressed.

## Scope

Candor ingests untrusted signal data (log lines, alert payloads, image metadata) that feeds into
LLM prompts. The main areas of security interest are:

- **Prompt injection**: anything that lets ingested telemetry alter the model's output shape
  rather than only its narrative content. Enrichment output (`internal/llm`) is grammar-constrained
  to a fixed hypotheses schema via the Anthropic API's structured outputs (see
  `internal/llm/anthropic`'s package doc) — there is no free-form output path for injected content
  to escape through. Action-taking (`ProposePullRequest`, shipped in `v0.1.0`) keeps the same
  constraint: the model's recommended action is read from the fixed catalog on `Hypothesis`, never
  executed directly, and a pull request only opens once the fix is independently, mechanically
  re-derived from the scan data (`internal/gitops.ComputeFix`) — the model's own output never
  authorizes a write on its own.
- **RBAC scope creep**: the operator's ServiceAccount is read-only by default; any change that
  grants it broader permissions is a security-relevant change, not a routine one.
- **Secrets handling**: the LLM API key (`ANTHROPIC_API_KEY`, sourced from the `candor-llm` Secret's
  `anthropic-api-key` key — see `charts/chart/values.yaml`'s `manager.env`), webhook URLs, and
  GitOps repo credentials. The key is optional at the Kubernetes level (`optional: true` on the
  `secretKeyRef`) precisely so a missing secret degrades to "no enrichment" rather than blocking
  pod startup - never treat a missing key as something to work around by relaxing that.
- **The GitOps write path**: anything that could cause a proposed pull request to be merged or
  applied without human review.
