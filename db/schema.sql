-- SecAgent canonical store (schema 1.1.0). SQL Server 2022 locally; Azure SQL Database in pilot.
-- Idempotent: safe to run on every start.
IF OBJECT_ID('dbo.Run') IS NULL CREATE TABLE dbo.Run (
  run_id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY, trigger_type NVARCHAR(20) NOT NULL, scope_json NVARCHAR(MAX) NOT NULL,
  budget_json NVARCHAR(MAX) NOT NULL, tokens INT NOT NULL DEFAULT 0, cost DECIMAL(18,6) NOT NULL DEFAULT 0,
  status NVARCHAR(40) NOT NULL, config_snapshot NVARCHAR(400) NOT NULL, trace_id NVARCHAR(64) NOT NULL,
  started_at DATETIME2 NOT NULL, ended_at DATETIME2 NULL, summary_json NVARCHAR(MAX) NULL);

IF OBJECT_ID('dbo.Finding') IS NULL CREATE TABLE dbo.Finding (
  finding_id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY, schema_version NVARCHAR(20) NOT NULL, source_scanner NVARCHAR(40) NOT NULL,
  scanner_version NVARCHAR(40) NOT NULL, scanner_rule_id NVARCHAR(200) NOT NULL, issue_type NVARCHAR(40) NOT NULL, title NVARCHAR(400) NOT NULL,
  cve_ids NVARCHAR(MAX) NULL, cwe_ids NVARCHAR(MAX) NULL, severity_scanner NVARCHAR(10) NOT NULL, severity_effective NVARCHAR(10) NULL,
  repo NVARCHAR(200) NOT NULL, branch NVARCHAR(200) NOT NULL, pr_number INT NULL, commit_sha NVARCHAR(64) NOT NULL,
  file_path NVARCHAR(500) NULL, line_start INT NULL, line_end INT NULL, component_name NVARCHAR(300) NULL, component_version NVARCHAR(100) NULL,
  fixed_version NVARCHAR(100) NULL, direct_or_transitive NVARCHAR(20) NULL, licence_id NVARCHAR(100) NULL, reachability NVARCHAR(20) NULL,
  exposure NVARCHAR(20) NULL, fingerprint CHAR(64) NOT NULL, fix_group_key NVARCHAR(64) NULL, occurrence_count INT NOT NULL,
  status NVARCHAR(30) NOT NULL, bucket NVARCHAR(20) NULL, first_seen DATETIME2 NOT NULL, last_seen DATETIME2 NOT NULL,
  owner_team NVARCHAR(100) NULL, classification NVARCHAR(20) NOT NULL, secret_hash NVARCHAR(80) NULL, code_snippet_ref NVARCHAR(500) NULL,
  raw_evidence_ref NVARCHAR(500) NOT NULL, sarif_ref NVARCHAR(200) NOT NULL, created_by_run UNIQUEIDENTIFIER NOT NULL,
  injection_flag BIT NOT NULL DEFAULT 0, message NVARCHAR(1000) NULL, attributes_json NVARCHAR(MAX) NULL, other_locations NVARCHAR(MAX) NULL,
  CONSTRAINT UQ_Finding_fingerprint UNIQUE (fingerprint));

IF OBJECT_ID('dbo.FindingOccurrence') IS NULL CREATE TABLE dbo.FindingOccurrence (
  id BIGINT IDENTITY PRIMARY KEY, finding_id UNIQUEIDENTIFIER NOT NULL, run_id UNIQUEIDENTIFIER NOT NULL, branch NVARCHAR(200) NOT NULL,
  commit_sha NVARCHAR(64) NOT NULL, file_path NVARCHAR(500) NULL, line_start INT NULL, sarif_ref NVARCHAR(200) NOT NULL, seen_at DATETIME2 NOT NULL);

IF OBJECT_ID('dbo.StatusHistory') IS NULL CREATE TABLE dbo.StatusHistory (
  id BIGINT IDENTITY PRIMARY KEY, finding_id UNIQUEIDENTIFIER NOT NULL, run_id UNIQUEIDENTIFIER NOT NULL, from_status NVARCHAR(30) NOT NULL,
  to_status NVARCHAR(30) NOT NULL, trigger_text NVARCHAR(400) NOT NULL, decided_by NVARCHAR(60) NOT NULL, at DATETIME2 NOT NULL, trace_id NVARCHAR(64) NULL);

IF OBJECT_ID('dbo.PolicyViolation') IS NULL CREATE TABLE dbo.PolicyViolation (
  id BIGINT IDENTITY PRIMARY KEY, run_id UNIQUEIDENTIFIER NULL, finding_id UNIQUEIDENTIFIER NULL, kind NVARCHAR(60) NOT NULL, details NVARCHAR(MAX) NOT NULL, at DATETIME2 NOT NULL);

IF OBJECT_ID('dbo.TriageDecision') IS NULL CREATE TABLE dbo.TriageDecision (
  decision_id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY, schema_version NVARCHAR(20) NOT NULL, run_id UNIQUEIDENTIFIER NOT NULL,
  finding_id UNIQUEIDENTIFIER NOT NULL, fix_group_key NVARCHAR(64) NULL, decision NVARCHAR(20) NOT NULL, proposed_decision NVARCHAR(20) NULL,
  bucket NVARCHAR(20) NOT NULL, severity_effective NVARCHAR(10) NOT NULL, reason NVARCHAR(1000) NOT NULL, confidence FLOAT NOT NULL,
  evidence_refs NVARCHAR(MAX) NOT NULL, agent_id NVARCHAR(60) NOT NULL, model_id NVARCHAR(100) NOT NULL, model_version NVARCHAR(100) NOT NULL,
  prompt_version NVARCHAR(100) NOT NULL, rule_pack_version NVARCHAR(100) NOT NULL, decided_at DATETIME2 NOT NULL, needs_human BIT NOT NULL,
  trace_id NVARCHAR(64) NOT NULL, context_pack_id UNIQUEIDENTIFIER NULL, routing_id UNIQUEIDENTIFIER NULL, idempotency_key NVARCHAR(300) NOT NULL,
  policy_notes NVARCHAR(1000) NULL);

IF OBJECT_ID('dbo.FixAttempt') IS NULL CREATE TABLE dbo.FixAttempt (
  fix_id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY, run_id UNIQUEIDENTIFIER NOT NULL, finding_ids NVARCHAR(MAX) NOT NULL, fix_group_key NVARCHAR(64) NULL,
  fixer_type NVARCHAR(40) NOT NULL, fixer_version NVARCHAR(60) NOT NULL, branch NVARCHAR(200) NOT NULL, pr_url NVARCHAR(500) NULL,
  attempt_no INT NOT NULL, verification_result NVARCHAR(20) NOT NULL, verification_evidence_refs NVARCHAR(MAX) NOT NULL,
  tokens_in INT NOT NULL, tokens_out INT NOT NULL, cost DECIMAL(18,6) NOT NULL, idempotency_key NVARCHAR(300) NOT NULL,
  context_pack_id UNIQUEIDENTIFIER NULL, routing_id UNIQUEIDENTIFIER NULL, created_at DATETIME2 NOT NULL, updated_at DATETIME2 NOT NULL,
  commit_sha NVARCHAR(64) NULL, failure_reason NVARCHAR(MAX) NULL, additions INT NOT NULL DEFAULT 0, deletions INT NOT NULL DEFAULT 0, files_changed INT NOT NULL DEFAULT 0);

IF OBJECT_ID('dbo.Evidence') IS NULL CREATE TABLE dbo.Evidence (
  evidence_id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY, type NVARCHAR(30) NOT NULL, uri NVARCHAR(500) NOT NULL, hash NVARCHAR(80) NOT NULL,
  related_ids NVARCHAR(MAX) NOT NULL, created_by NVARCHAR(60) NOT NULL, created_at DATETIME2 NOT NULL, trace_id NVARCHAR(64) NULL);

IF OBJECT_ID('dbo.RiskAcceptance') IS NULL CREATE TABLE dbo.RiskAcceptance (
  acceptance_id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY, finding_ids NVARCHAR(MAX) NULL, fix_group_key NVARCHAR(64) NULL,
  approver NVARCHAR(200) NOT NULL, reason NVARCHAR(1000) NOT NULL, compensating_control NVARCHAR(1000) NOT NULL, expiry_date DATE NOT NULL,
  approved_at DATETIME2 NOT NULL, evidence_id UNIQUEIDENTIFIER NOT NULL);  -- stub in slice 1 (no approval workflow yet)

IF OBJECT_ID('dbo.IdempotencyLedger') IS NULL CREATE TABLE dbo.IdempotencyLedger (
  [key] NVARCHAR(300) NOT NULL PRIMARY KEY, scope NVARCHAR(20) NOT NULL, status NVARCHAR(20) NOT NULL, result_ref NVARCHAR(1000) NULL,
  expires_at DATETIME2 NOT NULL, updated_at DATETIME2 NOT NULL);

IF OBJECT_ID('dbo.ContextPack') IS NULL CREATE TABLE dbo.ContextPack (
  context_pack_id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY, schema_version NVARCHAR(20) NOT NULL, run_id UNIQUEIDENTIFIER NOT NULL,
  finding_id UNIQUEIDENTIFIER NULL, fix_group_key NVARCHAR(64) NULL, agent_id NVARCHAR(60) NOT NULL, purpose NVARCHAR(20) NOT NULL,
  prompt_id NVARCHAR(60) NOT NULL, prompt_version NVARCHAR(20) NOT NULL, components_json NVARCHAR(MAX) NOT NULL, token_budget INT NOT NULL,
  token_total INT NOT NULL, masking_applied BIT NOT NULL, content_hash NVARCHAR(80) NOT NULL, created_at DATETIME2 NOT NULL,
  content_ref NVARCHAR(500) NULL, over_budget BIT NOT NULL DEFAULT 0);

IF OBJECT_ID('dbo.RoutingDecision') IS NULL CREATE TABLE dbo.RoutingDecision (
  routing_id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY, context_pack_id UNIQUEIDENTIFIER NOT NULL, run_id UNIQUEIDENTIFIER NOT NULL,
  task_type NVARCHAR(20) NOT NULL, required_quality NVARCHAR(20) NOT NULL, context_tokens INT NOT NULL, latency_target_ms INT NOT NULL,
  budget_remaining_json NVARCHAR(400) NOT NULL, candidate_models NVARCHAR(1000) NOT NULL, chosen_model_id NVARCHAR(100) NOT NULL,
  model_version NVARCHAR(100) NOT NULL, deployment NVARCHAR(100) NOT NULL, tier NVARCHAR(20) NOT NULL, reason NVARCHAR(1000) NOT NULL,
  fallback_used BIT NOT NULL, gateway_request_id NVARCHAR(200) NOT NULL, tokens_in INT NOT NULL, tokens_out INT NOT NULL,
  cost DECIMAL(18,6) NOT NULL, latency_ms INT NOT NULL, decided_at DATETIME2 NOT NULL, trace_id NVARCHAR(64) NOT NULL,
  span_id NVARCHAR(32) NOT NULL, outcome NVARCHAR(40) NOT NULL, schema_attempts INT NOT NULL DEFAULT 0);

IF OBJECT_ID('dbo.HumanTask') IS NULL CREATE TABLE dbo.HumanTask (
  task_id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY, run_id UNIQUEIDENTIFIER NOT NULL, type NVARCHAR(40) NOT NULL, title NVARCHAR(400) NOT NULL,
  details NVARCHAR(MAX) NOT NULL, finding_ids NVARCHAR(MAX) NOT NULL, owner NVARCHAR(200) NOT NULL, status NVARCHAR(20) NOT NULL, created_at DATETIME2 NOT NULL);

IF OBJECT_ID('dbo.RunEvent') IS NULL CREATE TABLE dbo.RunEvent (
  run_id UNIQUEIDENTIFIER NOT NULL, seq INT NOT NULL, json NVARCHAR(MAX) NOT NULL, CONSTRAINT PK_RunEvent PRIMARY KEY (run_id, seq));
