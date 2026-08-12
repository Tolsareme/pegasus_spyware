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

/// <summary>Shared prefix conventions for <see cref="Alert.EvidenceSummary"/> lines, so a
/// consumer (the GUI's notification-diffing logic) can tell a remediation action apart from a
/// routine rule-finding description without guessing at wording. A finding line looks like
/// <c>"[AEG-001] ..."</c> (the rule id); a remediation action line is prefixed with
/// <see cref="RemediationActionPrefix"/> instead.</summary>
public static class AlertEvidenceMarkers
{
    public const string RemediationActionPrefix = "[ACTION] ";
}

/// <summary>Manual action an operator (or, for <see cref="Remove"/>, the automatic-remediation
/// pipeline) can take against a specific alert. <see cref="Remove"/> and <see cref="Quarantine"/>
/// both act only on artifacts identified in that alert's own evidence events - never a
/// general-purpose cleanup pass over the host.</summary>
public enum AlertActionKind
{
    /// <summary>Full removal: terminate the offending process(es), quarantine the file(s) they
    /// ran from, disable any persistence artifact in the evidence, and block the flagged
    /// destination IP(s).</summary>
    Remove = 0,
    /// <summary>Lighter touch: quarantine the implicated file(s) only - leaves the process
    /// running and persistence artifacts untouched. Useful when you want the sample preserved
    /// (moved somewhere inert) without disrupting whatever else the process/service is doing.</summary>
    Quarantine = 1,
    /// <summary>No remediation - marks the alert FalsePositive/dismissed so it stops
    /// contributing to open-alert counts and coalescing.</summary>
    Ignore = 2,
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
