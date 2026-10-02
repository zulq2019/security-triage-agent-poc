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
