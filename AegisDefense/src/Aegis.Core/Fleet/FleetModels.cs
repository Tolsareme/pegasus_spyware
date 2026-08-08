namespace Aegis.Core.Fleet;

/// <summary>
/// A periodic, deliberately small summary one <c>Aegis.Service</c> instance sends to the
/// central Fleet Hub (v2) - doc §3.1's "cross-host or cross-service coordination" and
/// AutonomyScore's cross-host-coordination term need visibility across hosts that a single
/// isolated service can never have on its own. Sends rule IDs and a risk summary, never raw
/// events - the Hub is a correlation aid, not a second copy of the evidence store.
/// </summary>
public sealed record FleetHeartbeat
{
    public required string HostId { get; init; }
    public required DateTimeOffset Timestamp { get; init; }
    public required IReadOnlyList<string> RuleIdsFired { get; init; }
    public string? TopAttackState { get; init; }
    public double RiskScore { get; init; }
}

/// <summary>Per-rule "how many distinct hosts fired this recently" - the raw signal <c>DefenseEngine</c> turns into <see cref="Features.FeatureSnapshot.CrossHostSimilarHostCount"/>.</summary>
public sealed record FleetCorrelationSnapshot
{
    public required DateTimeOffset AsOf { get; init; }
    public required IReadOnlyDictionary<string, int> DistinctHostsByRuleId { get; init; }
}

public sealed record FleetHostStatus
{
    public required string HostId { get; init; }
    public required DateTimeOffset LastSeen { get; init; }
    public string? TopAttackState { get; init; }
    public double RiskScore { get; init; }
}

/// <summary>
/// Client-side seam for talking to the Fleet Hub. Implemented by <c>Aegis.Service</c>'s
/// HTTP client (net48-compatible, uses <c>HttpClient</c>); kept as an interface here so the
/// reporting/correlation-lookup logic in <c>DefenseEngine</c> is unit-testable against a
/// fake without a real HTTP server.
/// </summary>
public interface IFleetClient
{
    Task ReportHeartbeatAsync(FleetHeartbeat heartbeat, CancellationToken ct = default);

    Task<FleetCorrelationSnapshot?> GetCorrelationAsync(CancellationToken ct = default);
}

/// <summary>Used when fleet reporting is disabled in policy - every call is a safe no-op/empty result.</summary>
public sealed class NullFleetClient : IFleetClient
{
    public Task ReportHeartbeatAsync(FleetHeartbeat heartbeat, CancellationToken ct = default) => Task.CompletedTask;

    public Task<FleetCorrelationSnapshot?> GetCorrelationAsync(CancellationToken ct = default) =>
        Task.FromResult<FleetCorrelationSnapshot?>(null);
}
