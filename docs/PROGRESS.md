# Progress log (slice 1 tracer bullet)

Times are IST (UTC+5:30).

- 2026-10-02 ~20:00: All projects build (.NET 10 SDK, Microsoft.Agents.AI.* 1.23.0). Scanners, normaliser, context builder, model gateway, 4 fixers, Agent Framework workflow and RunService are written.
  - First real CLI run reached the verifier. Bugs found: (1) blob collision between two fix groups that share a fixer; (2) the test-fixture secret was fixed instead of suppressed, because the model ignored the matched suppression rule. Both are fixed: the verify label now includes the group key, and an AppSec-approved suppression rule decides when it matches.
- 2026-10-02 ~20:15: Live dashboard (mockup CSS reused) is written. Work is committed locally on `feature/slice-1-tracer-bullet`. Run 2 is in progress.
- 2026-10-02 ~20:46: **First full end-to-end dashboard run** (run 0ce09784, 9 min 25 s, 19.2k tokens). 3 fix PRs opened on the sample repo (#2 AWS key → Key Vault reference, #3 Newtonsoft.Json 13.0.1, #4 test-fixture key). The run paused at human review. Issues found:
  (a) The box ran out of memory in an earlier attempt (4 rescans plus 4 `dotnet test` runs next to ~10 GB of resident models). Verifications are now capped at 2 at a time, with no persistent build servers.
  (b) qwen2.5:3b raised the fixture key's severity to high, so the AppSec suppression rule no longer matched and PR #4 was opened in error. Rules are now judged at scanner severity. **PR #4 is wrong; the user should close it.**
  (c) The 3b model proposed suppressing the committed DLL with no rule. The policy layer correctly sent it to a human; rule-pack guidance is now explicit.
  (d) The unsafe fix used `SqlParameter` 3 times, so the build failed and it went to a human after retries. Guidance is now provider-specific, with a pre-build forbidden-type check and one repair call.
- 2026-10-02 ~21:00: **Clean end-to-end run** (9bcd4579, 8 min 25 s, 16.7k tokens): all 7 golden cases pass. Unsafe fix verified on attempt 1 (PR #5), binary removed (PR #6), fixture secret suppressed by rule (the model proposed "fix"), licence → human, PRs #2/#3 reused. 43/43 tests pass.
  - Added: model provider switch (ollama | openai | azureopenai, key from env only, 3b-only profile), Windows-safe tool lookup, `secagent export`, replay mode, `replay-static/`.
- 2026-10-02 ~21:11: D-06 re-run passed (6.9 s, 0 new PRs). Kill-switch test passed (stopped in 2.2 s; new runs refused). 43/43 tests pass. gitleaks (with a narrow repo allowlist) and trivy are clean on this repo.
  - Published the private repo `zulq2019/security-triage-agent-poc` (`main` = README only) and opened PR #1 from `feature/slice-1-tracer-bullet`. Not merged.
- 2026-10-02 ~22:15: **Usage observability**:
  - New `ModelUsage` table (migration 002, applied on start). Real calls are backfilled from `RoutingDecision` (14 real calls / 16,697 tokens from run 9bcd4579), and the gateway now writes a row per call. Triage decisions that are reused are recorded as zero-token cache hits.
  - Added `/api/usage/{summary,calls,calls.csv,budget,facets}` and the dashboard Usage tab: IST ranges, filters, KPIs, an SVG daily chart, by model/agent/task tables, budget burn vs `policies.yaml`, and recent calls with a run drill-down.
  - Price book with **placeholder** hosted prices in `models.yaml`. Synthetic seeding (`scripts/seed-usage.sh`, flagged `synthetic=1`, off by default) has a badge and a toggle. The replay export now carries per-call usage.
  - 21 new tests (cost, outcome mapping, IST boundaries, aggregation, budget burn, synthetic generator, SQL boundary/paging integration). 64/64 pass.
  - No new real run: re-runs on PR #1 reuse every triage decision and PR, so they make no model calls. The existing real calls were reused instead.
- 2026-10-02 ~22:20: **Code-review (Codex) fixes**, one commit per finding, each with regression tests:
  - P2: the replay export is now run-scoped. The rebuilt replay has the same 7 findings as the Vercel copy.
  - P1: fork PR heads are fetched via `refs/pull/<n>/head` and the head SHA is verified.
  - P1: fix/ledger keys are scoped by repo + PR + target ref, with a legacy fallback for the same repo.
  - P1: ledger PRs are revalidated before reuse (superseded otherwise); `--fresh` bypasses the reuse short-circuit.
  - P1: `max_fixes` and `max_minutes` are enforced, with a push gate and Guardrails rows.
  - 76/76 tests pass. No new live run: scoped keys would make a live re-run on the sample PR re-fix and open new GitHub PRs.
