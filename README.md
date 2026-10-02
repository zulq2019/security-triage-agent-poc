# Security Triage & Fix Agent — POC

Proof of concept of an agentic security triage and fix pipeline (PRD v0.2) for .NET repositories:
scanners → normalise (canonical Finding, SARIF-based) → orchestrator → triage → router → specialist fixers → verifier → human review.

Agents open pull requests only; they have no merge rights. Synthetic sample code and data only.

Work is delivered through feature branches and pull requests; see the open PRs.
