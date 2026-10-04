-- Migration 002: ModelUsage, one row per model call (usage / cost observability). Idempotent; applied on every start after schema.sql.
-- ts_utc is stored in UTC; the dashboard and API convert to IST (UTC+5:30, no DST) for display and for day boundaries.
-- synthetic = 1 marks demo rows written by scripts/seed-usage.sh (never by a real run). cache_hit = 1 marks a reused decision (no tokens spent).
IF OBJECT_ID('dbo.ModelUsage') IS NULL CREATE TABLE dbo.ModelUsage (
  usage_id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY, routing_id UNIQUEIDENTIFIER NULL, context_pack_id UNIQUEIDENTIFIER NULL,
  run_id UNIQUEIDENTIFIER NOT NULL, ts_utc DATETIME2 NOT NULL, repo NVARCHAR(200) NULL, pr_number INT NULL, mode NVARCHAR(20) NOT NULL,
  agent_id NVARCHAR(60) NOT NULL, task_purpose NVARCHAR(20) NOT NULL, tier NVARCHAR(20) NOT NULL, model_id NVARCHAR(100) NOT NULL,
  model_version NVARCHAR(100) NOT NULL, deployment NVARCHAR(100) NOT NULL, provider NVARCHAR(20) NOT NULL,
  input_tokens INT NOT NULL, output_tokens INT NOT NULL, total_tokens AS (input_tokens + output_tokens) PERSISTED,
  latency_ms INT NOT NULL, cost DECIMAL(18,6) NOT NULL, price_source NVARCHAR(20) NOT NULL, outcome NVARCHAR(20) NOT NULL,
  outcome_detail NVARCHAR(100) NULL, schema_attempts INT NOT NULL DEFAULT 0, fallback_used BIT NOT NULL DEFAULT 0,
  cache_hit BIT NOT NULL DEFAULT 0, synthetic BIT NOT NULL DEFAULT 0, trace_id NVARCHAR(64) NULL);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ModelUsage_ts' AND object_id = OBJECT_ID('dbo.ModelUsage'))
  CREATE INDEX IX_ModelUsage_ts ON dbo.ModelUsage (ts_utc) INCLUDE (run_id, agent_id, model_id, provider, input_tokens, output_tokens, cost, latency_ms, outcome, synthetic, cache_hit);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_ModelUsage_run' AND object_id = OBJECT_ID('dbo.ModelUsage'))
  CREATE INDEX IX_ModelUsage_run ON dbo.ModelUsage (run_id, ts_utc);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ModelUsage_routing' AND object_id = OBJECT_ID('dbo.ModelUsage'))
  CREATE UNIQUE INDEX UX_ModelUsage_routing ON dbo.ModelUsage (routing_id) WHERE routing_id IS NOT NULL;

-- Backfill: real calls recorded before this table existed (RoutingDecision + ContextPack + Run). Same outcome mapping as UsageMath.Outcome.
INSERT INTO dbo.ModelUsage (usage_id, routing_id, context_pack_id, run_id, ts_utc, repo, pr_number, mode, agent_id, task_purpose, tier, model_id,
  model_version, deployment, provider, input_tokens, output_tokens, latency_ms, cost, price_source, outcome, outcome_detail, schema_attempts,
  fallback_used, cache_hit, synthetic, trace_id)
SELECT NEWID(), rd.routing_id, rd.context_pack_id, rd.run_id, rd.decided_at, JSON_VALUE(r.scope_json, '$.repo'), TRY_CAST(JSON_VALUE(r.scope_json, '$.pr') AS INT),
  COALESCE(r.trigger_type, 'pr'), COALESCE(p.agent_id, 'unknown'), rd.task_type, rd.tier, rd.chosen_model_id, rd.model_version, rd.deployment,
  CASE WHEN r.config_snapshot LIKE '%+azureopenai%' THEN 'azureopenai' WHEN r.config_snapshot LIKE '%+openai%' THEN 'openai' ELSE 'ollama' END,
  rd.tokens_in, rd.tokens_out, rd.latency_ms, rd.cost,
  CASE WHEN r.config_snapshot LIKE '%+azureopenai%' OR r.config_snapshot LIKE '%+openai%' THEN (CASE WHEN rd.cost > 0 THEN 'config' ELSE 'none' END) ELSE 'local' END,
  CASE WHEN rd.outcome = 'ok' AND rd.schema_attempts > 1 THEN 'schema_retry' WHEN rd.outcome = 'ok' AND rd.fallback_used = 1 THEN 'fallback'
       WHEN rd.outcome = 'ok' THEN 'ok' WHEN rd.outcome LIKE '%Timeout%' OR rd.outcome LIKE '%TaskCanceled%' THEN 'timeout' ELSE 'error' END,
  CASE WHEN rd.outcome = 'ok' THEN NULL ELSE rd.outcome END, rd.schema_attempts, rd.fallback_used, 0, 0, rd.trace_id
FROM dbo.RoutingDecision rd LEFT JOIN dbo.ContextPack p ON p.context_pack_id = rd.context_pack_id LEFT JOIN dbo.Run r ON r.run_id = rd.run_id
WHERE rd.outcome <> 'pending' AND NOT EXISTS (SELECT 1 FROM dbo.ModelUsage u WHERE u.routing_id = rd.routing_id);

-- (fix-up for rows backfilled by an earlier build of this migration: outcome_detail is NULL for plain ok calls)
UPDATE dbo.ModelUsage SET outcome_detail = NULL WHERE outcome_detail = 'ok';
