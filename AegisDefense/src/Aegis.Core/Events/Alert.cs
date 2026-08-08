using Aegis.Core.Scoring;

namespace Aegis.Core.Events;

public enum AlertSeverity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

public enum AlertStatus
{
    New = 0,
    Acknowledged = 1,
    Investigating = 2,
    Contained = 3,
    Resolved = 4,
    FalsePositive = 5,
}

/// <summary>
/// A fused, human/GUI-facing incident. Alerts are produced by the rule engine, the
/// composite risk engine, or the attack-state estimator escalating a campaign -
/// never raw per-event noise. Every field needed for the "transparent evidence
/// trail" requirement in doc §12 is carried on the alert itself.
/// </summary>
public sealed class Alert
{
    public Guid AlertId { get; init; } = Guid.NewGuid();

    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

    public required string HostId { get; init; }

    public string? UserId { get; init; }

    public required string Title { get; init; }

    public required string Source { get; init; }

    public AlertSeverity Severity { get; set; } = AlertSeverity.Low;

    public AlertStatus Status { get; set; } = AlertStatus.New;

    public AttackState EstimatedState { get; set; } = AttackState.Benign;

    public double Confidence { get; set; }

    public HostRiskBreakdown? RiskBreakdown { get; set; }

    /// <summary>EventIds that support this alert - the evidence trail. Never empty for a real alert.</summary>
    public List<Guid> EvidenceEventIds { get; init; } = new();

    /// <summary>Human-readable evidence bullets shown in the GUI, generated alongside the score.</summary>
    public List<string> EvidenceSummary { get; init; } = new();

    public ResponseLevel RecommendedResponse { get; set; } = ResponseLevel.Observe;

    /// <summary>Set once a response action actually executes against this alert.</summary>
    public ResponseLevel? AppliedResponse { get; set; }

    public string? CampaignId { get; set; }
}
