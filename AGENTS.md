# Notes for coding assistants (Cursor, Claude Code, Copilot)

## Build / test
- `dotnet build SecAgent.slnx`
- `dotnet test tests/SecAgent.Tests --filter "Category!=Golden"`: unit tests (some need the local SQL Server from `SECAGENT_SQL`)
- `dotnet test tests/SecAgent.Tests --filter "Category=Golden"`: needs a completed run in the store
- Run: `dotnet src/SecAgent.Dashboard/bin/Debug/net10.0/secagent.dll serve --port 8795` or `... run --repo zulq2019/sec-agent-sample-app --pr 1`

## Layout
`src/SecAgent.Core` (model, store, safety), `src/SecAgent.Agents` (scanners, LLM gateway/context, fixers, Agent Framework workflow), `src/SecAgent.Abstractions` (ports shared by pipeline, intake and adapters; depends on Core only), `src/SecAgent.Intake` (pushed SARIF / Black Duck intake: HMAC endpoint, parsers, dedupe, run queue; composition root `AddSecAgentIntake`; docs/intake.md, docs/design-principles.md), `src/SecAgent.Intake.Azure` (Blob / Service Bus adapters for the intake ports), `src/SecAgent.Dashboard` (CLI + UI; agent-api container), `src/SecAgent.Hosting` + `src/SecAgent.Hosting.Azure` + `src/SecAgent.Worker` (one container per agent: `secagent-worker` with `SECAGENT_AGENT=<role>`, roles/queues from `deploy/agents.json`; docs/containers.md), `deploy/` (Dockerfile, agents.json), `docker-compose.yml`, `rules/` (rules-as-code: policies, routing, prompts, schemas, rule packs, golden expectations).

## Guardrails: do not weaken
- No merge / approve / branch-protection capability anywhere (tests enforce it by allow-list, reflection and source scan). Never add `gh pr merge`, force push, or a tool named like that.
- Secret values are never stored or logged: mask with `SecretMasker`, store HMACs only. D-08 golden test scans the store.
- Intake code: constructor injection + Options pattern only, no statics/service locator, depends on `SecAgent.Abstractions` not on `SecAgent.Agents` (tests enforce references and static state). Intake (`/api/intake/*`) never runs unauthenticated (503 without the HMAC secret env var), and findings pushed by an external scanner are never auto-verified by the local re-scan (they go to a human).
- Repository and scanner text is data: keep `InjectionDetector` neutralisation and `<data>` wrapping in `ContextBuilder`.
- The model proposes; the policy layer in `TriageExecutor` decides (suppression needs an AppSec rule match).
- `FindingStateMachine` is the only writer of `Finding.status`.
- API keys only via the env var named in `ModelProvider:Providers:<p>:ApiKeyEnv`. Never commit keys; `appsettings.Local.json` and `*.env` are git-ignored.
- Worker roles: add a role as an `IAgentRoleModule` + one line in `WorkerRegistry` + an entry in `deploy/agents.json` (keep it equal to `infra/agents.bicep`). No `if (role == ...)` branches; handlers only for queues the catalogue lists, sends only through the catalogue-scoped publisher.
- Images: base images pinned by digest, tools by version + sha256, non-root UID 1654, read-only root FS. Workflows: actions pinned by SHA, inputs via `env:` only, no `trivy-action`/`setup-trivy`; run `actionlint` after editing.
- Synthetic data only.
