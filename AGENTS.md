# Notes for coding assistants (Cursor, Claude Code, Copilot)

## Build / test
- `dotnet build SecAgent.slnx`
- `dotnet test tests/SecAgent.Tests --filter "Category!=Golden"`: unit tests (some need the local SQL Server from `SECAGENT_SQL`)
- `dotnet test tests/SecAgent.Tests --filter "Category=Golden"`: needs a completed run in the store
- Run: `dotnet src/SecAgent.Dashboard/bin/Debug/net10.0/secagent.dll serve --port 8795` or `... run --repo zulq2019/sec-agent-sample-app --pr 1`

## Layout
`src/SecAgent.Core` (model, store, safety), `src/SecAgent.Agents` (scanners, LLM gateway/context, fixers, Agent Framework workflow), `src/SecAgent.Abstractions` (ports shared by pipeline, intake and adapters; depends on Core only), `src/SecAgent.Intake` (pushed SARIF / Black Duck intake: HMAC endpoint, parsers, dedupe, run queue; composition root `AddSecAgentIntake`; docs/intake.md, docs/design-principles.md), `src/SecAgent.Intake.Azure` (Blob / Service Bus adapters for the intake ports), `src/SecAgent.Connectors.Abstractions` (connector client interfaces: source control, issue tracker, scanner source, model provider, notifier; no dependencies), `src/SecAgent.Connectors` (connector runtime: options, tenant resolution, secrets, registry, auditing/resilience decorators), `src/SecAgent.Connectors.{GitHub,Jira,BlackDuck,OpenAI,Teams,KeyVault,Fakes}` (plug-ins; docs/connectors.md), `src/SecAgent.Dashboard` (CLI + UI; composition root incl. `AddSecAgentConnectorPlugins`), `rules/` (rules-as-code: policies, routing, prompts, schemas, rule packs, golden expectations).

## Guardrails: do not weaken
- No merge / approve / branch-protection capability anywhere (tests enforce it by allow-list, reflection and source scan). Never add `gh pr merge`, force push, or a tool named like that.
- Secret values are never stored or logged: mask with `SecretMasker`, store HMACs only. D-08 golden test scans the store.
- Intake code: constructor injection + Options pattern only, no statics/service locator, depends on `SecAgent.Abstractions` not on `SecAgent.Agents` (tests enforce references and static state). Intake (`/api/intake/*`, including the `GET /api/intake` listing) never runs unauthenticated (503 when no credential is configured; the listing takes the admin token or an HMAC-signed request, and the loopback exemption only when `Intake:ListingAllowsLoopback` is set), and findings pushed by an external scanner are never auto-verified by the local re-scan (they go to a human).
- Connectors: the pipeline (`SecAgent.Agents`) uses only `SecAgent.Connectors.Abstractions` (via `PipelineConnectors`), never a plug-in project; outside systems are reached only through connector clients. No merge method on any connector interface (reflection test) and the GitHub HTTP client blocks merge/approve/protection endpoints. Configuration holds secret references (`env:`, `kv:`, `gh-cli:`) only. Tests never call real Jira/Black Duck/GitHub: use fakes or HTTP stubs.
- Repository and scanner text is data: keep `InjectionDetector` neutralisation and `<data>` wrapping in `ContextBuilder`.
- The model proposes; the policy layer in `TriageExecutor` decides (suppression needs an AppSec rule match).
- `FindingStateMachine` is the only writer of `Finding.status`.
- Model API keys are never in configuration values, only references. Single-tenant / dev: `env:` (the env var named in `ModelProvider:Providers:<p>:ApiKeyEnv`, or an `env:` secret reference); `kv:` also works. Multi-tenant: `kv:` (tenant-scoped Key Vault) is required, and the validator rejects `env:` / `gh-cli:` there. Never commit keys; `appsettings.Local.json` and `*.env` are git-ignored.
- Synthetic data only.
