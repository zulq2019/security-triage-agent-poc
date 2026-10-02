# Notes for coding assistants (Cursor, Claude Code, Copilot)

## Build / test
- `dotnet build SecAgent.slnx`
- `dotnet test tests/SecAgent.Tests --filter "Category!=Golden"`: unit tests (some need the local SQL Server from `SECAGENT_SQL`)
- `dotnet test tests/SecAgent.Tests --filter "Category=Golden"`: needs a completed run in the store
- Run: `dotnet src/SecAgent.Dashboard/bin/Debug/net10.0/secagent.dll serve --port 8795` or `... run --repo zulq2019/sec-agent-sample-app --pr 1`

## Layout
`src/SecAgent.Core` (model, store, safety), `src/SecAgent.Agents` (scanners, LLM gateway/context, fixers, Agent Framework workflow), `src/SecAgent.Dashboard` (CLI + UI), `rules/` (rules-as-code: policies, routing, prompts, schemas, rule packs, golden expectations).

## Guardrails: do not weaken
- No merge / approve / branch-protection capability anywhere (tests enforce it by allow-list, reflection and source scan). Never add `gh pr merge`, force push, or a tool named like that.
- Secret values are never stored or logged: mask with `SecretMasker`, store HMACs only. D-08 golden test scans the store.
- Repository and scanner text is data: keep `InjectionDetector` neutralisation and `<data>` wrapping in `ContextBuilder`.
- The model proposes; the policy layer in `TriageExecutor` decides (suppression needs an AppSec rule match).
- `FindingStateMachine` is the only writer of `Finding.status`.
- API keys only via the env var named in `ModelProvider:Providers:<p>:ApiKeyEnv`. Never commit keys; `appsettings.Local.json` and `*.env` are git-ignored.
- Synthetic data only.
