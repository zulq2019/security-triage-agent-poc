using System.Data;
using System.Text.Json;
using Dapper;
using Microsoft.Data.SqlClient;

namespace SecAgent.Core;

sealed class JsonHandler<T> : SqlMapper.TypeHandler<T>
{
    public override void SetValue(IDbDataParameter parameter, T? value) { parameter.DbType = DbType.String; parameter.Value = JsonSerializer.Serialize(value, Schema.Json); }
    public override T? Parse(object value) => value is string s && s.Length > 0 ? JsonSerializer.Deserialize<T>(s, Schema.Json) : default;
}

/// <summary>SQL Server store (Azure SQL in pilot). Single source of truth for findings, decisions, fixes, ledger, packs and routing.</summary>
public sealed class SqlStore
{
    readonly string _cs;
    static SqlStore()
    {
        DefaultTypeMap.MatchNamesWithUnderscores = true;
        SqlMapper.AddTypeHandler(new JsonHandler<List<string>>());
        SqlMapper.AddTypeHandler(new JsonHandler<List<Guid>>());
        SqlMapper.AddTypeHandler(new JsonHandler<Dictionary<string, string>>());
    }
    public SqlStore(string connectionString) { _cs = connectionString; }
    SqlConnection Open() { var c = new SqlConnection(_cs); c.Open(); return c; }

    public void EnsureSchema(string schemaFile)
    {
        using var c = Open();
        foreach (var stmt in File.ReadAllText(schemaFile).Split("\n\n", StringSplitOptions.RemoveEmptyEntries))
        {
            var sql = string.Join('\n', stmt.Split('\n').Where(l => !l.TrimStart().StartsWith("--")));
            if (!string.IsNullOrWhiteSpace(sql)) c.Execute(sql);
        }
    }

    /// <summary>Applies db/migrations/*.sql in name order after schema.sql (each migration is idempotent).</summary>
    public void EnsureMigrations(string migrationsDir)
    {
        if (!Directory.Exists(migrationsDir)) return;
        foreach (var f in Directory.GetFiles(migrationsDir, "*.sql").OrderBy(x => x, StringComparer.Ordinal)) EnsureSchema(f);
    }

    // ---------- Run ----------
    public void InsertRun(RunRecord r)
    {
        using var c = Open();
        c.Execute(@"INSERT INTO Run (run_id,trigger_type,scope_json,budget_json,tokens,cost,status,config_snapshot,trace_id,started_at)
                    VALUES (@RunId,@TriggerType,@ScopeJson,@BudgetJson,@Tokens,@Cost,@Status,@ConfigSnapshot,@TraceId,@StartedAt)", r);
    }
    public void UpdateRun(RunRecord r)
    {
        using var c = Open();
        c.Execute("UPDATE Run SET tokens=@Tokens,cost=@Cost,status=@Status,ended_at=@EndedAt,summary_json=@SummaryJson,trace_id=@TraceId WHERE run_id=@RunId", r);
    }
    public RunRecord? GetRun(Guid id) { using var c = Open(); return c.QuerySingleOrDefault<RunRecord>("SELECT * FROM Run WHERE run_id=@id", new { id }); }
    public RunRecord? LatestRun() { using var c = Open(); return c.QueryFirstOrDefault<RunRecord>("SELECT TOP 1 * FROM Run ORDER BY started_at DESC"); }
    public List<RunRecord> Runs(int n = 20) { using var c = Open(); return c.Query<RunRecord>("SELECT TOP (@n) * FROM Run ORDER BY started_at DESC", new { n }).ToList(); }

    // ---------- Finding ----------
    const string FindingCols = @"finding_id,schema_version,source_scanner,scanner_version,scanner_rule_id,issue_type,title,cve_ids,cwe_ids,severity_scanner,
        severity_effective,repo,branch,pr_number,commit_sha,file_path,line_start,line_end,component_name,component_version,fixed_version,direct_or_transitive,
        licence_id,reachability,exposure,fingerprint,fix_group_key,occurrence_count,status,bucket,first_seen,last_seen,owner_team,classification,secret_hash,
        code_snippet_ref,raw_evidence_ref,sarif_ref,created_by_run,injection_flag,message,attributes_json AS attributes,other_locations";

    public Finding? FindingByFingerprint(string fp) { using var c = Open(); return c.QuerySingleOrDefault<Finding>($"SELECT {FindingCols} FROM Finding WHERE fingerprint=@fp", new { fp }); }
    public Finding? GetFinding(Guid id) { using var c = Open(); return c.QuerySingleOrDefault<Finding>($"SELECT {FindingCols} FROM Finding WHERE finding_id=@id", new { id }); }
    public List<Finding> ListFindings() { using var c = Open(); return c.Query<Finding>($"SELECT {FindingCols} FROM Finding ORDER BY last_seen DESC").ToList(); }

    /// <summary>Dedupe by fingerprint: insert NEW or link an occurrence to the existing record.</summary>
    public (Finding Stored, bool IsNew) UpsertFinding(Finding f, Guid runId)
    {
        using var c = Open();
        var existing = c.QuerySingleOrDefault<Finding>($"SELECT {FindingCols} FROM Finding WHERE fingerprint=@Fingerprint", new { f.Fingerprint });
        if (existing is null)
        {
            c.Execute(@"INSERT INTO Finding (finding_id,schema_version,source_scanner,scanner_version,scanner_rule_id,issue_type,title,cve_ids,cwe_ids,severity_scanner,
                severity_effective,repo,branch,pr_number,commit_sha,file_path,line_start,line_end,component_name,component_version,fixed_version,direct_or_transitive,
                licence_id,reachability,exposure,fingerprint,fix_group_key,occurrence_count,status,bucket,first_seen,last_seen,owner_team,classification,secret_hash,
                code_snippet_ref,raw_evidence_ref,sarif_ref,created_by_run,injection_flag,message,attributes_json,other_locations)
                VALUES (@FindingId,@SchemaVersion,@SourceScanner,@ScannerVersion,@ScannerRuleId,@IssueType,@Title,@CveIds,@CweIds,@SeverityScanner,
                @SeverityEffective,@Repo,@Branch,@PrNumber,@CommitSha,@FilePath,@LineStart,@LineEnd,@ComponentName,@ComponentVersion,@FixedVersion,@DirectOrTransitive,
                @LicenceId,@Reachability,@Exposure,@Fingerprint,@FixGroupKey,@OccurrenceCount,@Status,@Bucket,@FirstSeen,@LastSeen,@OwnerTeam,@Classification,@SecretHash,
                @CodeSnippetRef,@RawEvidenceRef,@SarifRef,@CreatedByRun,@InjectionFlag,@Message,@Attributes,@OtherLocations)", f);
            AddOccurrence(c, f, runId);
            return (f, true);
        }
        c.Execute(@"UPDATE Finding SET last_seen=@LastSeen, occurrence_count=occurrence_count+1, branch=@Branch, pr_number=@PrNumber, commit_sha=@CommitSha,
                    line_start=@LineStart, line_end=@LineEnd, raw_evidence_ref=@RawEvidenceRef, sarif_ref=@SarifRef, code_snippet_ref=COALESCE(@CodeSnippetRef,code_snippet_ref),
                    attributes_json=@Attributes, other_locations=@OtherLocations WHERE finding_id=@Id",
            new { f.LastSeen, f.Branch, f.PrNumber, f.CommitSha, f.LineStart, f.LineEnd, f.RawEvidenceRef, f.SarifRef, f.CodeSnippetRef, f.Attributes, f.OtherLocations, Id = existing.FindingId });
        f.FindingId = existing.FindingId;
        AddOccurrence(c, f, runId);
        return (GetFinding(existing.FindingId)!, false);
    }

    static void AddOccurrence(SqlConnection c, Finding f, Guid runId) =>
        c.Execute(@"INSERT INTO FindingOccurrence (finding_id,run_id,branch,commit_sha,file_path,line_start,sarif_ref,seen_at)
                    VALUES (@FindingId,@runId,@Branch,@CommitSha,@FilePath,@LineStart,@SarifRef,SYSUTCDATETIME())", new { f.FindingId, runId, f.Branch, f.CommitSha, f.FilePath, f.LineStart, f.SarifRef });

    public void SetInjectionFlag(Guid id) { using var c = Open(); c.Execute("UPDATE Finding SET injection_flag=1 WHERE finding_id=@id", new { id }); }
    public void SetTriageFields(Guid id, string severityEffective, string bucket) { using var c = Open(); c.Execute("UPDATE Finding SET severity_effective=@severityEffective, bucket=@bucket WHERE finding_id=@id", new { id, severityEffective, bucket }); }

    /// <summary>Status write with optimistic concurrency. Called only by the Orchestrator's state machine.</summary>
    internal bool WriteStatus(Guid id, string from, string to, string trigger, string by, Guid runId)
    {
        using var c = Open();
        using var tx = c.BeginTransaction();
        var n = c.Execute("UPDATE Finding SET status=@to WHERE finding_id=@id AND status=@from", new { id, from, to }, tx);
        if (n == 1)
            c.Execute(@"INSERT INTO StatusHistory (finding_id,run_id,from_status,to_status,trigger_text,decided_by,at,trace_id)
                        VALUES (@id,@runId,@from,@to,@trigger,@by,SYSUTCDATETIME(),@trace)", new { id, runId, from, to, trigger, by, trace = Telemetry.TraceId }, tx);
        tx.Commit();
        return n == 1;
    }
    public void PolicyViolation(Guid? runId, Guid? findingId, string kind, string details)
    {
        using var c = Open();
        c.Execute("INSERT INTO PolicyViolation (run_id,finding_id,kind,details,at) VALUES (@runId,@findingId,@kind,@details,SYSUTCDATETIME())", new { runId, findingId, kind, details });
    }
    public List<dynamic> StatusHistory(Guid findingId) { using var c = Open(); return c.Query("SELECT * FROM StatusHistory WHERE finding_id=@findingId ORDER BY id", new { findingId }).ToList(); }

    // ---------- Decisions / fixes / evidence ----------
    public void InsertDecision(TriageDecision d)
    {
        using var c = Open();
        c.Execute(@"INSERT INTO TriageDecision (decision_id,schema_version,run_id,finding_id,fix_group_key,decision,proposed_decision,bucket,severity_effective,reason,confidence,
            evidence_refs,agent_id,model_id,model_version,prompt_version,rule_pack_version,decided_at,needs_human,trace_id,context_pack_id,routing_id,idempotency_key,policy_notes)
            VALUES (@DecisionId,@SchemaVersion,@RunId,@FindingId,@FixGroupKey,@Decision,@ProposedDecision,@Bucket,@SeverityEffective,@Reason,@Confidence,
            @EvidenceRefs,@AgentId,@ModelId,@ModelVersion,@PromptVersion,@RulePackVersion,@DecidedAt,@NeedsHuman,@TraceId,@ContextPackId,@RoutingId,@IdempotencyKey,@PolicyNotes)", d);
    }
    public TriageDecision? LatestDecision(Guid findingId) { using var c = Open(); return c.QueryFirstOrDefault<TriageDecision>("SELECT TOP 1 * FROM TriageDecision WHERE finding_id=@findingId ORDER BY decided_at DESC", new { findingId }); }
    public TriageDecision? DecisionByKey(string key) { using var c = Open(); return c.QueryFirstOrDefault<TriageDecision>("SELECT TOP 1 * FROM TriageDecision WHERE idempotency_key=@key ORDER BY decided_at DESC", new { key }); }
    public List<TriageDecision> DecisionsForRun(Guid runId) { using var c = Open(); return c.Query<TriageDecision>("SELECT * FROM TriageDecision WHERE run_id=@runId", new { runId }).ToList(); }

    public void InsertFix(FixAttempt f)
    {
        using var c = Open();
        c.Execute(@"INSERT INTO FixAttempt (fix_id,run_id,finding_ids,fix_group_key,fixer_type,fixer_version,branch,pr_url,attempt_no,verification_result,verification_evidence_refs,
            tokens_in,tokens_out,cost,idempotency_key,context_pack_id,routing_id,created_at,updated_at,commit_sha,failure_reason,additions,deletions,files_changed)
            VALUES (@FixId,@RunId,@FindingIds,@FixGroupKey,@FixerType,@FixerVersion,@Branch,@PrUrl,@AttemptNo,@VerificationResult,@VerificationEvidenceRefs,
            @TokensIn,@TokensOut,@Cost,@IdempotencyKey,@ContextPackId,@RoutingId,@CreatedAt,@UpdatedAt,@CommitSha,@FailureReason,@Additions,@Deletions,@FilesChanged)", f);
    }
    public void UpdateFix(FixAttempt f)
    {
        f.UpdatedAt = DateTime.UtcNow;
        using var c = Open();
        c.Execute(@"UPDATE FixAttempt SET pr_url=@PrUrl, verification_result=@VerificationResult, verification_evidence_refs=@VerificationEvidenceRefs, tokens_in=@TokensIn,
            tokens_out=@TokensOut, cost=@Cost, updated_at=@UpdatedAt, commit_sha=@CommitSha, failure_reason=@FailureReason, additions=@Additions, deletions=@Deletions,
            files_changed=@FilesChanged, context_pack_id=@ContextPackId, routing_id=@RoutingId WHERE fix_id=@FixId", f);
    }
    public FixAttempt? GetFix(Guid id) { using var c = Open(); return c.QuerySingleOrDefault<FixAttempt>("SELECT * FROM FixAttempt WHERE fix_id=@id", new { id }); }
    public List<FixAttempt> FixesForRun(Guid runId) { using var c = Open(); return c.Query<FixAttempt>("SELECT * FROM FixAttempt WHERE run_id=@runId ORDER BY created_at", new { runId }).ToList(); }
    public List<FixAttempt> FixesForFinding(Guid findingId) { using var c = Open(); return c.Query<FixAttempt>("SELECT * FROM FixAttempt WHERE finding_ids LIKE @p ORDER BY created_at", new { p = "%" + findingId + "%" }).ToList(); }

    public void InsertEvidence(Evidence e)
    {
        using var c = Open();
        c.Execute("INSERT INTO Evidence (evidence_id,type,uri,hash,related_ids,created_by,created_at,trace_id) VALUES (@EvidenceId,@Type,@Uri,@Hash,@RelatedIds,@CreatedBy,@CreatedAt,@TraceId)", e);
    }
    public List<Evidence> AllEvidence() { using var c = Open(); return c.Query<Evidence>("SELECT * FROM Evidence").ToList(); }

    /// <summary>Dev/demo only: clears all SecAgent tables in the local database.</summary>
    public void ResetAll()
    {
        using var c = Open();
        c.Execute("IF OBJECT_ID('dbo.ModelUsage') IS NOT NULL DELETE FROM dbo.ModelUsage");
        foreach (var t in new[] { "RunEvent", "HumanTask", "RoutingDecision", "ContextPack", "IdempotencyLedger", "RiskAcceptance", "Evidence", "FixAttempt",
                     "TriageDecision", "PolicyViolation", "StatusHistory", "FindingOccurrence", "Finding", "Run" })
            c.Execute($"DELETE FROM dbo.{t}");
    }

    // ---------- Idempotency ledger ----------
    public sealed record LedgerEntry(string Key, string Scope, string Status, string? ResultRef);
    /// <summary>Takes the key if free (or previously failed). Returns the existing entry if it is in progress / completed.</summary>
    public LedgerEntry? TryTake(string key, string scope, TimeSpan ttl)
    {
        using var c = Open();
        var e = c.QuerySingleOrDefault<LedgerEntry>("SELECT [key] AS [Key], scope, status, result_ref AS ResultRef FROM IdempotencyLedger WHERE [key]=@key", new { key });
        if (e is not null && e.Status == "in_progress" && c.ExecuteScalar<int>("SELECT CASE WHEN expires_at < SYSUTCDATETIME() THEN 1 ELSE 0 END FROM IdempotencyLedger WHERE [key]=@key", new { key }) == 1)
            e = e with { Status = "failed" }; // stale lock from a crashed run: take it over
        if (e is not null && e.Status != "failed") return e;
        if (e is null)
            c.Execute("INSERT INTO IdempotencyLedger ([key],scope,status,expires_at,updated_at) VALUES (@key,@scope,'in_progress',@exp,SYSUTCDATETIME())", new { key, scope, exp = DateTime.UtcNow + ttl });
        else
            c.Execute("UPDATE IdempotencyLedger SET status='in_progress', expires_at=@exp, updated_at=SYSUTCDATETIME() WHERE [key]=@key", new { key, exp = DateTime.UtcNow + ttl });
        return null;
    }
    public void LedgerComplete(string key, string? resultRef) { using var c = Open(); c.Execute("UPDATE IdempotencyLedger SET status='completed', result_ref=@resultRef, updated_at=SYSUTCDATETIME() WHERE [key]=@key", new { key, resultRef }); }
    public void LedgerFail(string key, string? reason) { using var c = Open(); c.Execute("UPDATE IdempotencyLedger SET status='failed', result_ref=@reason, updated_at=SYSUTCDATETIME() WHERE [key]=@key", new { key, reason }); }
    public LedgerEntry? Ledger(string key) { using var c = Open(); return c.QuerySingleOrDefault<LedgerEntry>("SELECT [key] AS [Key], scope, status, result_ref AS ResultRef FROM IdempotencyLedger WHERE [key]=@key", new { key }); }

    // ---------- Context packs / routing ----------
    public void InsertContextPack(ContextPack p)
    {
        using var c = Open();
        c.Execute(@"INSERT INTO ContextPack (context_pack_id,schema_version,run_id,finding_id,fix_group_key,agent_id,purpose,prompt_id,prompt_version,components_json,token_budget,
            token_total,masking_applied,content_hash,created_at,content_ref,over_budget) VALUES (@ContextPackId,@SchemaVersion,@RunId,@FindingId,@FixGroupKey,@AgentId,@Purpose,
            @PromptId,@PromptVersion,@ComponentsJson,@TokenBudget,@TokenTotal,@MaskingApplied,@ContentHash,@CreatedAt,@ContentRef,@OverBudget)",
            new { p.ContextPackId, p.SchemaVersion, p.RunId, p.FindingId, p.FixGroupKey, p.AgentId, p.Purpose, p.PromptId, p.PromptVersion,
                  ComponentsJson = JsonSerializer.Serialize(p.Components, Schema.Json), p.TokenBudget, p.TokenTotal, p.MaskingApplied, p.ContentHash, p.CreatedAt, p.ContentRef, p.OverBudget });
    }
    public void InsertRouting(RoutingDecision r)
    {
        using var c = Open();
        c.Execute(@"INSERT INTO RoutingDecision (routing_id,context_pack_id,run_id,task_type,required_quality,context_tokens,latency_target_ms,budget_remaining_json,candidate_models,
            chosen_model_id,model_version,deployment,tier,reason,fallback_used,gateway_request_id,tokens_in,tokens_out,cost,latency_ms,decided_at,trace_id,span_id,outcome,schema_attempts)
            VALUES (@RoutingId,@ContextPackId,@RunId,@TaskType,@RequiredQuality,@ContextTokens,@LatencyTargetMs,@BudgetRemainingJson,@CandidateModels,@ChosenModelId,@ModelVersion,
            @Deployment,@Tier,@Reason,@FallbackUsed,@GatewayRequestId,@TokensIn,@TokensOut,@Cost,@LatencyMs,@DecidedAt,@TraceId,@SpanId,@Outcome,@SchemaAttempts)", r);
    }
    public List<dynamic> RoutingForRun(Guid runId) { using var c = Open(); return c.Query("SELECT * FROM RoutingDecision WHERE run_id=@runId ORDER BY decided_at", new { runId }).ToList(); }
    public List<dynamic> PacksForRun(Guid runId) { using var c = Open(); return c.Query("SELECT * FROM ContextPack WHERE run_id=@runId", new { runId }).ToList(); }

    // ---------- Model usage (one row per model call) ----------
    const string UsageInsert = @"INSERT INTO ModelUsage (usage_id,routing_id,context_pack_id,run_id,ts_utc,repo,pr_number,mode,agent_id,task_purpose,tier,model_id,model_version,
        deployment,provider,input_tokens,output_tokens,latency_ms,cost,price_source,outcome,outcome_detail,schema_attempts,fallback_used,cache_hit,synthetic,trace_id)
        VALUES (@UsageId,@RoutingId,@ContextPackId,@RunId,@TsUtc,@Repo,@PrNumber,@Mode,@AgentId,@TaskPurpose,@Tier,@ModelId,@ModelVersion,
        @Deployment,@Provider,@InputTokens,@OutputTokens,@LatencyMs,@Cost,@PriceSource,@Outcome,@OutcomeDetail,@SchemaAttempts,@FallbackUsed,@CacheHit,@Synthetic,@TraceId)";
    public void InsertUsage(ModelUsage u) { using var c = Open(); c.Execute(UsageInsert, u); }
    public int InsertUsageBatch(IEnumerable<ModelUsage> rows)
    {
        using var c = Open();
        using var tx = c.BeginTransaction();
        var n = c.Execute(UsageInsert, rows, tx);
        tx.Commit();
        return n;
    }
    public int DeleteSyntheticUsage() { using var c = Open(); return c.Execute("DELETE FROM ModelUsage WHERE synthetic = 1"); }
    /// <summary>Test helper: removes rows for the given (test-only) run ids.</summary>
    public int DeleteUsageForRuns(IEnumerable<Guid> runIds) { using var c = Open(); return c.Execute("DELETE FROM ModelUsage WHERE run_id = @id", runIds.Select(id => new { id })); }

    static (string Where, DynamicParameters P) UsageWhere(UsageFilter f)
    {
        var (from, to) = f.Window;
        var p = new DynamicParameters(new { from, to });
        var w = new List<string> { "ts_utc >= @from", "ts_utc < @to" };
        if (!string.IsNullOrEmpty(f.Model)) { w.Add("model_id = @model"); p.Add("model", f.Model); }
        if (!string.IsNullOrEmpty(f.Agent)) { w.Add("agent_id = @agent"); p.Add("agent", f.Agent); }
        if (!string.IsNullOrEmpty(f.Provider)) { w.Add("provider = @provider"); p.Add("provider", f.Provider); }
        if (!string.IsNullOrEmpty(f.Task)) { w.Add("task_purpose = @task"); p.Add("task", f.Task); }
        if (f.Run is { } run) { w.Add("run_id = @run"); p.Add("run", run); }
        if (f.Synthetic == "exclude") w.Add("synthetic = 0");
        else if (f.Synthetic == "only") w.Add("synthetic = 1");
        return (" WHERE " + string.Join(" AND ", w), p);
    }
    static ModelUsage Utc(ModelUsage u) { u.TsUtc = DateTime.SpecifyKind(u.TsUtc, DateTimeKind.Utc); return u; }

    public List<ModelUsage> QueryUsage(UsageFilter f)
    {
        var (where, p) = UsageWhere(f);
        using var c = Open();
        return c.Query<ModelUsage>("SELECT * FROM ModelUsage" + where + " ORDER BY ts_utc", p).Select(Utc).ToList();
    }
    public (int Total, List<ModelUsage> Items) QueryUsagePage(UsageFilter f, int page, int pageSize)
    {
        var (where, p) = UsageWhere(f);
        p.Add("skip", Math.Max(0, page - 1) * pageSize); p.Add("take", pageSize);
        using var c = Open();
        var total = c.ExecuteScalar<int>("SELECT COUNT(*) FROM ModelUsage" + where, p);
        var items = c.Query<ModelUsage>("SELECT * FROM ModelUsage" + where + " ORDER BY ts_utc DESC, usage_id OFFSET @skip ROWS FETCH NEXT @take ROWS ONLY", p).Select(Utc).ToList();
        return (total, items);
    }
    /// <summary>Distinct filter values in the window (synthetic toggle applied, other filters not), for the dashboard dropdowns.</summary>
    public object UsageFacets(UsageFilter f)
    {
        var (where, p) = UsageWhere(new UsageFilter { From = f.From, To = f.To, Synthetic = f.Synthetic });
        using var c = Open();
        return new
        {
            models = c.Query<(string, string)>("SELECT DISTINCT model_id, provider FROM ModelUsage" + where + " ORDER BY model_id", p).Select(x => new { model = x.Item1, provider = x.Item2 }),
            agents = c.Query<string>("SELECT DISTINCT agent_id FROM ModelUsage" + where + " ORDER BY agent_id", p),
            runs = c.Query("SELECT run_id, MAX(repo) AS repo, MAX(pr_number) AS pr_number, MAX(CAST(synthetic AS INT)) AS synthetic, MAX(ts_utc) AS last_utc FROM ModelUsage" + where +
                           " GROUP BY run_id ORDER BY MAX(ts_utc) DESC", p).Take(200),
            any_synthetic = c.ExecuteScalar<int>("SELECT COUNT(*) FROM ModelUsage WHERE synthetic = 1") > 0,
        };
    }

    // ---------- Human tasks ----------
    public void InsertTask(HumanTask t)
    {
        using var c = Open();
        c.Execute("INSERT INTO HumanTask (task_id,run_id,type,title,details,finding_ids,owner,status,created_at) VALUES (@TaskId,@RunId,@Type,@Title,@Details,@FindingIds,@Owner,@Status,@CreatedAt)", t);
    }
    public List<HumanTask> TasksForRun(Guid runId) { using var c = Open(); return c.Query<HumanTask>("SELECT * FROM HumanTask WHERE run_id=@runId", new { runId }).ToList(); }
    public List<HumanTask> TasksForFinding(Guid findingId) { using var c = Open(); return c.Query<HumanTask>("SELECT * FROM HumanTask WHERE finding_ids LIKE @p", new { p = "%" + findingId + "%" }).ToList(); }

    // ---------- Run events ----------
    public void InsertEvent(Guid runId, int seq, string json) { using var c = Open(); c.Execute("INSERT INTO RunEvent (run_id,seq,json) VALUES (@runId,@seq,@json)", new { runId, seq, json }); }
    public List<string> Events(Guid runId, int afterSeq = 0) { using var c = Open(); return c.Query<string>("SELECT json FROM RunEvent WHERE run_id=@runId AND seq>@afterSeq ORDER BY seq", new { runId, afterSeq }).ToList(); }

    /// <summary>Text dump of all text columns, used by the D-08 "no secret values in stores" check.</summary>
    public IEnumerable<string> AllText()
    {
        using var c = Open();
        foreach (var t in new[] { "Finding", "TriageDecision", "FixAttempt", "Evidence", "ContextPack", "RoutingDecision", "HumanTask", "RunEvent", "Run", "IdempotencyLedger", "StatusHistory", "ModelUsage" })
            foreach (IDictionary<string, object> row in c.Query($"SELECT * FROM {t}"))
                foreach (var v in row.Values) if (v is string s) yield return s;
    }
}

/// <summary>The only writer of Finding.status (section 7.9). Rejects and logs any transition not in the table.</summary>
public sealed class FindingStateMachine(SqlStore store)
{
    static readonly HashSet<(string, string)> Allowed =
    [
        (Status.New, Status.Triaged), (Status.New, Status.Duplicate), (Status.Triaged, Status.FixQueued), (Status.Triaged, Status.Suppressed),
        (Status.Triaged, Status.SuppressPending), (Status.SuppressPending, Status.Suppressed), (Status.SuppressPending, Status.Triaged),
        (Status.Triaged, Status.AcceptPending), (Status.AcceptPending, Status.RiskAccepted), (Status.AcceptPending, Status.Triaged),
        (Status.Triaged, Status.NeedsHuman), (Status.NeedsHuman, Status.Triaged), (Status.FixQueued, Status.FixInProgress),
        (Status.FixInProgress, Status.FixProposed), (Status.FixProposed, Status.Verified), (Status.FixProposed, Status.VerifyFailed),
        (Status.VerifyFailed, Status.FixInProgress), (Status.VerifyFailed, Status.NeedsHuman), (Status.Verified, Status.Resolved),
        (Status.RiskAccepted, Status.Reopened), (Status.Resolved, Status.Reopened), (Status.Suppressed, Status.Reopened), (Status.Reopened, Status.Triaged),
        // Slice-1 additions (documented): a fixer may hand a licence decision to a human; a fix in progress can fail before verification.
        (Status.FixInProgress, Status.NeedsHuman), (Status.FixQueued, Status.NeedsHuman),
    ];

    public static bool IsAllowed(string from, string to) => Allowed.Contains((from, to));

    public void Transition(Guid runId, Finding f, string to, string trigger, string decidedBy)
    {
        var from = f.Status;
        if (from == to) return;
        if (!Allowed.Contains((from, to)))
        {
            store.PolicyViolation(runId, f.FindingId, "illegal_transition", $"{from} -> {to} ({trigger}) by {decidedBy}");
            throw new InvalidOperationException($"Illegal status transition {from} -> {to} for finding {f.Short}");
        }
        if (!store.WriteStatus(f.FindingId, from, to, trigger, decidedBy, runId))
            throw new InvalidOperationException($"Concurrent status change for finding {f.Short} (expected {from})");
        f.Status = to;
    }
}
