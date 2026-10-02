# Security Triage & Fix Agent: POC (slice 1 tracer bullet)

An agentic pipeline that triages security findings on a .NET pull request and opens **verified fix PRs** for a human to review:

scanners → canonical Finding (SARIF-based) → orchestrator → triage agent (+ deterministic policy layer) → router → 4 specialist fixers → verifier (rescan + `dotnet test` + evidence) → one fix PR per fix group → **human review**.

Agents open PRs only. They have no merge rights, and no code path can merge. The sample code and data are synthetic, and every "secret" is fake.

- Runtime: **Microsoft Agent Framework 1.23.0** (`Microsoft.Agents.AI`, `.Workflows`, `.OpenAI`; GA) on .NET 10
- Models: local Ollama (`qwen2.5:3b` small tier, `qwen2.5-coder:7b` strong tier, `qwen2.5-coder:3b` fallback) behind a thin model gateway. Moving to Azure OpenAI/APIM is a config change.
- Scanners: gitleaks 8.30.1, trivy 0.75.0 (vuln + licence), semgrep 1.179.0 (custom C# SQLi rule), binary check
- Store: SQL Server 2022 (local), standing in for Azure SQL. Evidence goes to a write-once local blob folder, standing in for Azure Blob.
- Live dashboard: ASP.NET + SSE (`secagent serve`)

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design, the Azure mapping and the guardrails, [docs/RESULTS.md](docs/RESULTS.md) for the real run results, and [docs/PROGRESS.md](docs/PROGRESS.md) for the build log.

## Run it

Prerequisites: .NET 10 SDK, Ollama with the three models pulled, SQL Server (local), gitleaks/trivy/semgrep on `PATH`, and `gh` signed in with push access to the sample repo.

```bash
# one-time: local secrets file (never committed)
mkdir -p ~/.secagent && cat > ~/.secagent/secagent.env <<'ENV'
SECAGENT_SQL=Server=localhost;Database=SecAgent;User Id=secagent_app;Password=<local>;TrustServerCertificate=true
SECAGENT_HMAC_KEY=<random 32+ chars>
ENV
chmod 600 ~/.secagent/secagent.env

dotnet build SecAgent.slnx
dotnet src/SecAgent.Dashboard/bin/Debug/net10.0/secagent.dll reset-db          # dev only: creates the schema / clears demo data
dotnet src/SecAgent.Dashboard/bin/Debug/net10.0/secagent.dll serve --port 8795  # dashboard → http://localhost:8795, "Run on PR #1"
# or headless:
dotnet src/SecAgent.Dashboard/bin/Debug/net10.0/secagent.dll run --repo zulq2019/sec-agent-sample-app --pr 1
```

Tests:

```bash
dotnet test tests/SecAgent.Tests --filter "Category!=Golden"   # unit tests (needs local SQL + Ollama for the context/routing tests)
dotnet test tests/SecAgent.Tests --filter "Category=Golden"    # golden tests against the latest completed run in the store
scripts/rerun-check.sh                                          # D-06: re-run on the same PR opens no duplicate PRs
```

Environment knobs: `SECAGENT_PORT`, `SECAGENT_VERIFY_PARALLEL` (default 2), `OTEL_EXPORTER_OTLP_ENDPOINT`, `SECAGENT_OTEL_CONSOLE=1`.
Traces are written as JSONL to `.data/traces/`. Evidence and context packs go to `.data/blob/evidence/<run>/`.
