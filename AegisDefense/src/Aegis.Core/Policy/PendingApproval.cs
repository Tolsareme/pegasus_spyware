namespace Aegis.Core.Policy;

public enum ApprovalResolution
{
    Pending = 0,
    Approved = 1,
    Rejected = 2,
    Expired = 3,
}

/// <summary>
/// A high-impact response decision waiting on a human/GUI operator (doc §14: "should
/// require explicit policy approval or human authorization"). Created by the response
/// pipeline whenever <see cref="ResponseDecision.RequiresHumanApproval"/> is true and no
/// emergency-playbook entry matched.
/// </summary>
public sealed class PendingApproval
{
    public Guid ApprovalId { get; init; } = Guid.NewGuid();
    public required string HostId { get; init; }
    public required Guid AlertId { get; init; }
    public required Events.ResponseLevel RequestedLevel { get; init; }
    public required IReadOnlyList<string> Rationale { get; init; }
    public DateTimeOffset RequestedAt { get; init; } = DateTimeOffset.UtcNow;

    public ApprovalResolution Resolution { get; set; } = ApprovalResolution.Pending;
    public DateTimeOffset? ResolvedAt { get; set; }
    public string? ResolvedBy { get; set; }
    public string? ResolutionNote { get; set; }
}
