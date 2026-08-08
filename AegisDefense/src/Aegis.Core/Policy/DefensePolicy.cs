using Aegis.Core.Events;
using Aegis.Core.Scoring;

namespace Aegis.Core.Policy;

/// <summary>Which detection/response engines are currently active - the GUI's autonomy control surface (task: "the rest need to be autonomous with options the gui to control them").</summary>
public sealed class EngineToggles
{
    public bool RuleEngineEnabled { get; set; } = true;
    public bool AnomalyEngineEnabled { get; set; } = true;
    public bool GraphEngineEnabled { get; set; } = true;
    public bool AttackStateEstimationEnabled { get; set; } = true;
    public bool AutonomyScoringEnabled { get; set; } = true;
    public bool DeceptionEnabled { get; set; } = true;
    public bool VulnerabilityIntelEnabled { get; set; } = true;
    public bool AutoContainmentEnabled { get; set; } = false; // opt-in: off by default, an operator must consciously enable automated containment
    public bool VirtualMitigationEnabled { get; set; } = false;
}

/// <summary>Composite-risk (0-100) cut points that select a <see cref="ResponseLevel"/>. Mirrors the doc §14 risk/mode table.</summary>
public sealed class ResponseThresholds
{
    public double EnrichAt { get; set; } = 30;
    public double RestrictAt { get; set; } = 50;
    public double ContainAt { get; set; } = 70;
    public double EnterpriseResponseAt { get; set; } = 85;
}

/// <summary>Where (if anywhere) alerts and audit entries are forwarded as CEF-over-syslog (v2) - see <see cref="Aegis.Core.Siem.ISiemForwarder"/>.</summary>
public sealed class SiemForwardingSettings
{
    public bool Enabled { get; set; } = false;
    public string? Host { get; set; }
    public int Port { get; set; } = 514;
    public bool UseTcp { get; set; } = false;
    /// <summary>Included in every forwarded CEF header as the reporting device's product/vendor identity.</summary>
    public string DeviceVendor { get; set; } = "AegisDefense";
}

/// <summary>Central Fleet Hub connection settings (v2) - see <see cref="Aegis.Core.Fleet.IFleetClient"/>. The API key is a shared secret; production deployments spanning untrusted networks should additionally put the Hub behind mutual TLS (see docs/ARCHITECTURE.md).</summary>
public sealed class FleetSettings
{
    public bool Enabled { get; set; } = false;
    public string? HubUrl { get; set; }
    public string? ApiKey { get; set; }
    public int ReportingIntervalSeconds { get; set; } = 60;
}

/// <summary>
/// A specific high-impact action pre-authorized to run without live human sign-off, e.g.
/// "isolate a designated test endpoint" from the MVP scope (doc §24). Anything not
/// explicitly listed here stays gated behind approval even if the risk score alone
/// would justify it - this is the "narrowly defined emergency playbook" doc §14 allows.
/// </summary>
public sealed class EmergencyPlaybookEntry
{
    public required string ActionId { get; set; }
    public required string Description { get; set; }
    public string? HostIdScope { get; set; } // null = applies to any host; set to restrict to e.g. a canary/test endpoint
}

/// <summary>
/// The full, signable configuration document the Windows Service loads at startup and the
/// GUI edits (subject to re-signing). This is the "narrow, deterministic response API with
/// signed policies" required by doc §29.
/// </summary>
public sealed class DefensePolicy
{
    public string PolicyId { get; set; } = Guid.NewGuid().ToString();
    public int Version { get; set; } = 1;
    public DateTimeOffset IssuedAt { get; set; } = DateTimeOffset.UtcNow;
    public string Issuer { get; set; } = "unset";

    public EngineToggles Engines { get; set; } = new();
    public ResponseThresholds Thresholds { get; set; } = new();
    public bool HighImpactActionsRequireApproval { get; set; } = true;
    public List<EmergencyPlaybookEntry> EmergencyPlaybook { get; set; } = new();

    /// <summary>Raw events older than this are pruned (v2 retention/rollup); alerts and the audit log are never pruned by this setting. 0 disables pruning.</summary>
    public int EventRetentionDays { get; set; } = 90;

    /// <summary>SIEM forwarding target (v2). Null/empty host disables forwarding.</summary>
    public SiemForwardingSettings Siem { get; set; } = new();

    /// <summary>Central Fleet Hub reporting (v2) - enables cross-host correlation. Disabled by default; a single isolated host works fully without one.</summary>
    public FleetSettings Fleet { get; set; } = new();

    public AutonomyScoreWeights AutonomyWeights { get; set; } = AutonomyScoreWeights.Default;
    public HostRiskWeights RiskWeights { get; set; } = HostRiskWeights.Default;

    /// <summary>Base64 RSA-SHA256 signature over the canonical JSON of every field above. Null/empty = unsigned (rejected by the service unless running in dev/insecure mode).</summary>
    public string? Signature { get; set; }

    public static DefensePolicy CreateDefault(string issuer = "aegis-default") => new()
    {
        Issuer = issuer,
        EmergencyPlaybook =
        {
            new EmergencyPlaybookEntry
            {
                ActionId = "isolate-test-endpoint",
                Description = "Reversibly isolate a designated test/canary endpoint from the network while preserving management connectivity (doc §24 MVP scope).",
                HostIdScope = null,
            },
        },
    };
}
