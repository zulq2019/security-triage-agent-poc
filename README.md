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

## Model provider: a pure config switch

`src/SecAgent.Dashboard/appsettings.json` → `ModelProvider` (overridable by `appsettings.Local.json`, which is git-ignored, and by env vars):

| Setting | Env var | Values |
|---|---|---|
| `Provider` | `SECAGENT_MODEL_PROVIDER` | `ollama` (default) · `openai` · `azureopenai` |
| `LocalProfile` (ollama only) | `SECAGENT_LOCAL_PROFILE` | `default` = qwen2.5:3b + qwen2.5-coder:7b (~10 GB RAM resident) · `3b-only` = qwen2.5-coder:3b for both tiers (~3 GB) |
| `Providers.<p>.BaseUrl` | `SECAGENT_MODEL_BASE_URL` | e.g. `https://api.openai.com/v1`, `https://<res>.openai.azure.com/openai/v1/` |
| `Providers.<p>.SmallModel` / `StrongModel` | `SECAGENT_SMALL_MODEL` / `SECAGENT_STRONG_MODEL` | OpenAI defaults are **placeholders** (`gpt-6-luna` / `gpt-6.1-sol`): set them to the models on your account. For Azure, use your deployment names |
| `Providers.<p>.ApiKeyEnv` | (the key itself) | `OPENAI_API_KEY` / `AZURE_OPENAI_API_KEY`. **The key is read only from that environment variable and is never written to a file, a log or the store** |

Only the provider, endpoint and models change. The routing policy (task → tier, escalation, budgets, schema validation, kill switch) stays in `rules/gateway/models.yaml`. The provider choice is part of the hashed config snapshot that every run records. Hosted providers default to `MaxConcurrentCalls: 4`, no temperature/seed (reasoning-family models reject them), a 4096-token output reserve and a 250k-token run budget.

## Windows laptop (16 GB) with the OpenAI API

> Written for Windows 10/11 + PowerShell. The code is cross-platform (.NET 10; the tool lookup handles `PATHEXT`; paths are normalised so fingerprints match across OSes), but this POC was built and run on Linux. A Windows run has **not** been tested yet.

1. **Tools** (PowerShell):
   ```powershell
   winget install Microsoft.DotNet.SDK.10
   winget install Git.Git
   winget install GitHub.cli
   winget install --id Gitleaks.Gitleaks -e
   winget install --id AquaSecurity.Trivy -e
   winget install Python.Python.3.12          # then, in a NEW terminal:
   python -m pip install semgrep              # semgrep has no winget package; native Windows support is recent. WSL is the fallback
   gh auth login                              # GitHub.com → HTTPS → browser; needs push + PR rights on the sample repo
   gitleaks version; trivy --version; semgrep --version; dotnet --version
   ```
   Run `trivy fs --download-db-only` once so the first scan doesn't stall on the DB download.
2. **SQL Server**, either:
   - **LocalDB** (lightest): install *SQL Server Express LocalDB* (SQL Server Express installer → "Download Media" → LocalDB, or the Visual Studio Installer), plus `winget install Microsoft.Sqlcmd`, then
     ```powershell
     sqllocaldb start MSSQLLocalDB
     sqlcmd -S "(localdb)\MSSQLLocalDB" -Q "CREATE DATABASE SecAgent"
     $sql = 'Server=(localdb)\MSSQLLocalDB;Database=SecAgent;Integrated Security=true;TrustServerCertificate=true'
     ```
   - **Docker Desktop**:
     ```powershell
     docker run -d --name secagent-sql -m 2g -e ACCEPT_EULA=Y -e "MSSQL_SA_PASSWORD=<StrongLocalPassw0rd!>" -p 1433:1433 mcr.microsoft.com/mssql/server:2022-latest
     docker exec secagent-sql /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "<StrongLocalPassw0rd!>" -C -Q "CREATE DATABASE SecAgent"
     $sql = 'Server=localhost,1433;Database=SecAgent;User Id=sa;Password=<StrongLocalPassw0rd!>;TrustServerCertificate=true'
     ```
3. **Secrets in environment variables** (user scope, persisted; open a new terminal afterwards). Nothing goes into the repo:
   ```powershell
   [Environment]::SetEnvironmentVariable('OPENAI_API_KEY', '<your key>', 'User')
   [Environment]::SetEnvironmentVariable('SECAGENT_SQL', $sql, 'User')
   [Environment]::SetEnvironmentVariable('SECAGENT_HMAC_KEY', [Convert]::ToBase64String([byte[]](1..32 | % { Get-Random -Max 256 })), 'User')
   [Environment]::SetEnvironmentVariable('SECAGENT_MODEL_PROVIDER', 'openai', 'User')
   # optional: pick models without editing files
   [Environment]::SetEnvironmentVariable('SECAGENT_SMALL_MODEL', '<small model>', 'User')
   [Environment]::SetEnvironmentVariable('SECAGENT_STRONG_MODEL', '<strong model>', 'User')
   ```
   For the current session only, use `$env:OPENAI_API_KEY = '<your key>'`. Alternatively, put the non-OpenAI values in `%USERPROFILE%\.secagent\secagent.env` (`KEY=value` lines), which the app loads at startup.
4. **Build and run** (from the repo root):
   ```powershell
   dotnet build SecAgent.slnx
   dotnet src\SecAgent.Dashboard\bin\Debug\net10.0\secagent.dll reset-db
   dotnet src\SecAgent.Dashboard\bin\Debug\net10.0\secagent.dll serve --port 8795    # http://localhost:8795 → Run on PR #1
   dotnet test tests\SecAgent.Tests --filter "Category!=Golden"
   ```
   Fix PRs that already exist on the sample repo are found and **reused** (no duplicates). Expect "reused" for those groups.
5. **Local models on the laptop instead** (no API key): install Ollama, `ollama pull qwen2.5-coder:3b` and `ollama pull qwen2.5:3b`, then set `SECAGENT_MODEL_PROVIDER=ollama` and `SECAGENT_LOCAL_PROFILE=3b-only`. The `default` local profile (7b) needs ~10 GB for models alone, which is too much next to SQL Server, the scanners and `dotnet test` on 16 GB.

## Open in Cursor or Claude Code

- **Cursor:** `git clone https://github.com/zulq2019/security-triage-agent-poc && cd security-triage-agent-poc && git checkout feature/slice-1-tracer-bullet && cursor .` (or File → Open Folder). Install the C# Dev Kit extension when prompted; open `SecAgent.slnx`.
- **Claude Code:** in the repo root run `claude`. `CLAUDE.md` points at `AGENTS.md` (build/test commands, layout and the guardrails an assistant must not weaken).
- Both tools inherit your shell environment, so start them from a terminal where `OPENAI_API_KEY` / `SECAGENT_SQL` are set (or set them at user scope as above).

## Usage: model calls, tokens and cost

Every model call writes one `ModelUsage` row (`db/migrations/002_model_usage.sql`, applied on start; rows recorded before the table existed are backfilled from `RoutingDecision` + `ContextPack` + `Run`). A row holds the UTC timestamp (shown in IST), run id, repo/PR, mode, agent, task purpose (triage/fix/verify/summarise), tier, model id + version, deployment, provider, input/output/total tokens, latency, cost, price source, outcome (`ok` · `schema_retry` · `fallback` · `error` · `timeout`) and a cache-hit flag. Cache hits are triage decisions reused without a model call, so they spend zero tokens.

- **Cost** = input/1k × `cost_per_1k_in` + output/1k × `cost_per_1k_out`. Local Ollama models are always **$0** and are tagged "local model". Hosted providers use the deployment's own price (appsettings `*CostPer1kIn/Out`) if one is set. Otherwise they use the `price_book` in `rules/gateway/models.yaml`. **The prices in that book are placeholders, not real prices**: rows priced from it carry `price_source = placeholder`, and the UI tags them "placeholder price".
- **Dashboard → Usage tab**:
  - range Today / 7 days / 30 days / custom (IST calendar days), plus model / agent / run filters
  - KPI cards: calls, input and output tokens, cost, avg/p95 latency, error and retry rate
  - a daily stacked input/output token chart with a cost line (inline SVG, no CDN)
  - by-model / by-agent / by-task tables with % of total
  - budget burn against `policies.yaml` (per-run token cap, `usage_budgets` daily/monthly tokens and monthly cost, month-end projection)
  - a paged recent-calls table with a run drill-down
  - Export CSV
- **API** (all take `range=today|7d|30d` or `from=YYYY-MM-DD&to=YYYY-MM-DD` (IST, inclusive), `model`, `agent`, `provider`, `task`, `run`, `synthetic=include|exclude|only`):
  - `GET /api/usage/summary?groupBy=model|agent|task|run|day|provider`
  - `GET /api/usage/calls?page=1&pageSize=25`
  - `GET /api/usage/calls.csv`
  - `GET /api/usage/budget`
  - `GET /api/usage/facets`
- **Synthetic demo data** (only one real run with model calls exists so far): `scripts/seed-usage.sh` (or `.ps1`) writes about 30 days of plausible usage for the Ollama models and the OpenAI/Azure placeholder models from config. Every row is flagged `synthetic = 1` and uses `synthetic-org/*` repos. It is **not seeded by default**. When synthetic rows are in view the tab shows a "Synthetic sample data in view" badge, and the "Show synthetic" toggle hides them. Remove them with `scripts/seed-usage.sh --clear`.
- **Replay**: `secagent export` adds the run's per-call usage (real rows) and the usage policy to `run.json`; `--usage-sample <days>` also adds a columnar SYNTHETIC sample (same generator as `seed-usage`, seed 42, every row `synthetic`, ending on the run's IST day). `scripts/build-replay.sh` passes `--usage-sample 30` (set `USAGE_SAMPLE_DAYS=0` for real usage only). In replay mode `app.js` runs the same filters and aggregation as `/api/usage/*` in the browser (range Today/7d/30d/custom anchored at the run's IST day, model/agent/run filters, synthetic toggle, run drill-down, client-side CSV export); default view is 30 days with the synthetic sample on, labelled as such, with placeholder prices tagged.
- Screenshots: `shots/usage-real-only*.png`, `shots/usage-synthetic-30d*.png`, `shots/usage-synthetic-7d*.png`, `shots/usage-replay.png` (`scripts/capture-usage.js`).

## Replay a recorded run (no backend)

`replay-static/` holds a static build of the clean run (`index.html` + `run.json` + `run.js` + `assets/app.js`). Open `replay-static/index.html` in a browser (works from `file://`) or serve the folder with any static server. The dashboard plays back the real event stream with its recorded timings, with 1×/2× speed and a Replay button, and is marked "Replay of a recorded run". Rebuild it from any run with `scripts/build-replay.sh [run-id]` (uses `secagent export`, which refuses to write if a secret pattern is found). The replay also has a **Trends** tab after Usage (replay only, **sample data, illustrative**: every number, repo, team and CVE id is synthetic, CVE-SAMPLE-*; KPI targets are placeholders). It is generated by `scripts/build-trends-sample.py` (ported from the trends mockup) into `src/SecAgent.Dashboard/replay/trends.html`, and `build-replay.sh` injects it; deep link `?tab=trends` (works for any tab). It also has a **Connections** tab after Trends (replay only, **mockup: not connected to real systems**): connector cards (GitHub, Black Duck, Azure OpenAI / OpenAI, Jira, Microsoft Teams, Azure Key Vault, plus a coming-soon row), a searchable *Add connector* picker, a 4-step connect flow for GitHub/Jira (access requested, repos/projects, where secrets live, done), per-repo settings and a Wipro-hosted / Customer-hosted switch. All state is in-browser only and resets on reload; no network calls, tokens or OAuth. Source `src/SecAgent.Dashboard/replay/connections.html`, injected by `build-replay.sh`; deep link `?tab=connections`. A copy (absolute `/security-agent/` paths) is deployed behind basic auth as the `/security-agent` section of the demo site (`security-agent-demo.vercel.app`).

## Run it (Linux / this box)

Prerequisites: .NET 10 SDK, Ollama with the models pulled (or a hosted provider, see above), SQL Server (local), gitleaks/trivy/semgrep on `PATH`, and `gh` signed in with push access to the sample repo.

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
