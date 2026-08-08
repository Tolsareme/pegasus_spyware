namespace Aegis.Data;

internal static class Schema
{
    public const string CreateStatements = @"
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    host_id TEXT NOT NULL,
    user_id TEXT NULL,
    process_id INTEGER NULL,
    parent_process_id INTEGER NULL,
    process_hash TEXT NULL,
    signer TEXT NULL,
    image_path TEXT NULL,
    parent_image_path TEXT NULL,
    host_role TEXT NULL,
    logon_type INTEGER NULL,
    action_type TEXT NOT NULL,
    object_type TEXT NOT NULL,
    object_id TEXT NULL,
    source_ip TEXT NULL,
    destination_ip TEXT NULL,
    destination_port INTEGER NULL,
    privilege_context TEXT NULL,
    result TEXT NOT NULL,
    confidence REAL NOT NULL,
    raw_event_reference TEXT NULL,
    command_line TEXT NULL,
    tags_json TEXT NULL,
    sequence INTEGER NULL,
    chain_hash TEXT NULL,
    prev_chain_hash TEXT NULL
);
CREATE INDEX IF NOT EXISTS ix_events_host_time ON events(host_id, timestamp);
CREATE INDEX IF NOT EXISTS ix_events_time ON events(timestamp);
CREATE UNIQUE INDEX IF NOT EXISTS ix_events_sequence ON events(sequence);

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    host_id TEXT NOT NULL,
    user_id TEXT NULL,
    title TEXT NOT NULL,
    source TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    estimated_state TEXT NOT NULL,
    confidence REAL NOT NULL,
    risk_breakdown_json TEXT NULL,
    evidence_event_ids_json TEXT NOT NULL,
    evidence_summary_json TEXT NOT NULL,
    recommended_response TEXT NOT NULL,
    applied_response TEXT NULL,
    campaign_id TEXT NULL
);
CREATE INDEX IF NOT EXISTS ix_alerts_host_time ON alerts(host_id, created_at);
CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts(status);

CREATE TABLE IF NOT EXISTS policies (
    policy_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 0,
    policy_json TEXT NOT NULL,
    stored_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_policies_active ON policies(is_active);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    host_id TEXT NOT NULL,
    component TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    cve_id TEXT NOT NULL DEFAULT '',
    priority_score REAL NOT NULL,
    record_json TEXT NOT NULL,
    computed_at TEXT NOT NULL,
    PRIMARY KEY (host_id, component, installed_version, cve_id)
);
CREATE INDEX IF NOT EXISTS ix_vulnerabilities_priority ON vulnerabilities(priority_score DESC);

CREATE TABLE IF NOT EXISTS decoys (
    decoy_id TEXT PRIMARY KEY,
    decoy_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_approvals (
    approval_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    alert_id TEXT NOT NULL,
    requested_level TEXT NOT NULL,
    rationale_json TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    resolution TEXT NOT NULL DEFAULT 'Pending',
    resolved_at TEXT NULL,
    resolved_by TEXT NULL,
    resolution_note TEXT NULL
);
CREATE INDEX IF NOT EXISTS ix_approvals_resolution ON pending_approvals(resolution);

CREATE TABLE IF NOT EXISTS patch_rollout_plans (
    plan_id TEXT PRIMARY KEY,
    component TEXT NOT NULL,
    stage TEXT NOT NULL,
    plan_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_patch_plans_stage ON patch_rollout_plans(stage);
";
}
