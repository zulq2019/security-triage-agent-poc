# Architecture: slice 1 tracer bullet

One PR-mode run, end to end, on a synthetic repo. Everything runs on one box: no cloud and no public deployment.

```
GitHub PR ──► Scanners (gitleaks, trivy, semgrep, binary check) on head + base worktrees, in parallel
              │  normalise → canonical Finding (SARIF-based, schema 1.1.0) + fingerprint (no line numbers)
              ▼
          Orchestrator (no LLM): dedupe by fingerprint, PR scope = new vs base, upsert, plan
              ▼
          Triage agent (LLM, JSON-schema output) + policy layer (code, not model)
              │  suppression rules / severity floors / confidence threshold / "never lower a secret"
              ▼
          Router (no LLM): registry lookup, fix groups, idempotency ledger
              ▼
   ┌──────────┬───────────┬───────────────┬────────────────────┐
   Library    Secrets     Unsafe code     Binary / Licence      fixers, each in its own git worktree
   └──────────┴───────────┴───────────────┴────────────────────┘
              ▼
          Verifier: rescan the fix branch (target gone, nothing new), dotnet test (trx), evidence blobs,
              │     small-model summary. Fail → retry the fixer (max 2) → then a human task
              ▼
          Orchestrator: push branch, open ONE PR per fix group (base = the PR's head branch), idempotent
              ▼
          Human review (RequestPort): the run stops at "awaiting_human_review". Agents cannot merge.
```

## Building blocks

| Concern | Implementation (POC) | Pilot on Azure |
|---|---|---|
| Agent runtime / workflow | Microsoft Agent Framework 1.23.0 (`Microsoft.Agents.AI`, `.Workflows`, GA). Typed executors, conditional edges, `RequestPort` for human review, `FileSystemJsonCheckpointStore` | Same code; durable checkpoints in Blob / Cosmos DB; host in Azure Container Apps (jobs for scans, app for dashboard) |
| Model calls | `ChatClientAgent` over the OpenAI-compatible client → local Ollama (`qwen2.5:3b`, `qwen2.5-coder:7b`, `qwen2.5-coder:3b`) | Azure OpenAI deployments behind the APIM AI gateway. Provider switch `ModelProvider` in appsettings/env: `ollama` · `openai` · `azureopenai` (no code change; key only from an env var) |
| Model gateway | `ModelGateway`: tier routing (task → tier, escalate on high severity / retry / low confidence), per-tier failover, circuit breaker, run token budget, schema validation and repair retries, a `RoutingDecision` row per call | APIM `llm-token-limit`, `llm-emit-token-metric`, backend pools |
| Context | `ContextBuilder`: one `ContextPack` per call, with required/optional components, a token budget, trim order, masking, injection neutralisation, a content hash, and the pack stored | Same; packs in Blob (evidence container) |
| Queue between scanners and orchestrator | In-process channel `queue.publish("findings")` | Azure Service Bus queue/topic |
| Store | SQL Server 2022 (local) via Dapper: Finding, StatusHistory, TriageDecision, FixAttempt, Evidence, ContextPack, RoutingDecision, HumanTask, IdempotencyLedger, RunEvent | Azure SQL Database |
| Evidence / raw output | Write-once local folder `.data/blob/{raw,evidence}` with sha256 | Azure Blob with immutability policy |
| Config | Rules-as-code under `rules/` (policies, routing, gateway, context, rule packs, prompts, schemas), hashed into a config snapshot label on every run | Azure App Configuration snapshot + feature flags (kill switch, per-repo enablement) |
| Secrets | `~/.secagent/secagent.env` (chmod 600): SQL connection string and HMAC key. Secret values are never stored, only HMACs | Key Vault (HMAC key, GitHub App key); secrets fixer writes Key Vault references |
| Telemetry | OpenTelemetry spans (workflow, executors, tools, GenAI client) → JSONL in `.data/traces`, OTLP if `OTEL_EXPORTER_OTLP_ENDPOINT` set | Application Insights / Azure Monitor |
| GitHub | `gh` CLI as the signed-in user: `git push` of `fix/*` branches, `gh pr create`, `gh pr list` for idempotency. No merge/approve tool exists | GitHub App with contents:write + pull_requests:write only, branch protection on `main` |
| Kill switch | `.data/control/killswitch` flag + dashboard toggle: refuses tool calls and cancels in-flight model calls | App Configuration feature flag |

## Guardrails (what the code enforces, not the model)

- **No merge.** No agent allow-list has a merge/approve tool, and no method in the codebase can merge (tests check by reflection and source scan). PRs are opened against the PR's head branch, never against `main`.
- **Tool allow-lists** per agent (`rules/routing/routing.yaml`). An out-of-list call throws and writes a `PolicyViolation`.
- **State machine.** `FindingStateMachine` is the only writer of `Finding.status`. Illegal transitions are refused and logged.
- **Secrets.** Values are masked before every model call, log, event, DB row and PR body. The store holds HMACs only. Golden test D-08 scans every text column, blob and trace.
- **Prompt injection.** Instruction-like text in repo content is detected, flagged on the finding (`injection_flag`), replaced in the context pack, and wrapped in `<data>` tags. The policy layer, not the model, decides suppressions, and a suppression needs a matching AppSec-approved rule.
- **Budgets.** Run token budget, max fixes, max minutes. A high-quality task is never downgraded when budget is low; the run stops instead.
- **Retries.** Max 2 fixer retries per group. After that the group goes to a human (`fix_failed` task).
- **Idempotency.** The ledger (`fix:<group>:pr`) plus a `gh pr list` lookup mean re-runs reuse PRs. Branches are never force-pushed; if a branch exists without a PR, a run-suffixed branch is used.

## Source map

| Path | What |
|---|---|
| `src/SecAgent.Core` | Model (canonical schema), Config snapshot, Hashing/Fingerprints, Safety (masker, injection detector, tokens), Store + state machine, Infra (blob, kill switch, telemetry), Events (live feed) |
| `src/SecAgent.Agents/Scanners` | Adapters for gitleaks / trivy / semgrep / binary check → canonical findings + SARIF |
| `src/SecAgent.Agents/Llm` | ContextBuilder, ModelGateway, LlmStep (pack → route → call → validate → record) |
| `src/SecAgent.Agents/Fixers` | Library, Secrets, UnsafeCode, BinaryLicence fixers |
| `src/SecAgent.Agents/Workflow` | Agent Framework executors, workflow graph, RunService (checkpoints, kill switch, review) |
| `src/SecAgent.Dashboard` | `secagent` CLI + ASP.NET dashboard (SSE live feed, findings, controls) |
| `rules/` | Rules-as-code: policies, routing, gateway, context, rule packs, prompts, JSON schemas, golden expectations |
| `db/schema.sql` | Store schema (idempotent) |
| `tests/SecAgent.Tests` | Unit + golden tests |
| `scripts/` | `capture-run.js` (dashboard screenshots), `rerun-check.sh` (D-06) |
