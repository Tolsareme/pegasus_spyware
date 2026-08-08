namespace Aegis.Core.Response;

public sealed record ResponseActionResult
{
    public required bool Success { get; init; }
    public required string Detail { get; init; }
    public bool Reversible { get; init; } = true;
    public DateTimeOffset ExecutedAt { get; init; } = DateTimeOffset.UtcNow;
    /// <summary>Opaque token the same executor can use to reverse this action later (e.g. the firewall rule name).</summary>
    public string? RollbackToken { get; init; }
}

public sealed record FirewallRestriction(string RuleName, string Direction, string Protocol, string? RemoteAddress, int? RemotePort, string Action);

/// <summary>
/// The full menu of bounded, reversible containment/mitigation actions doc §14/§17 allow an
/// autonomous or approved decision to take. Every method is scoped to a single host and a
/// single concrete action - there is deliberately no "run arbitrary command" method, so the
/// policy engine's decisions are the only path to privileged effect (doc §29: "execution
/// should occur only through a narrow, deterministic response API"). Implemented by
/// <c>Aegis.ResponseActions</c> (Windows-only); this interface itself has zero OS
/// dependencies so response *decisions* remain unit-testable against a fake.
/// </summary>
public interface IResponseExecutor
{
    Task<ResponseActionResult> IsolateEndpointAsync(string hostId, bool preserveManagementConnectivity, CancellationToken ct = default);

    Task<ResponseActionResult> ReleaseIsolationAsync(string hostId, CancellationToken ct = default);

    Task<ResponseActionResult> TerminateProcessAsync(string hostId, int processId, string? expectedImagePath, CancellationToken ct = default);

    Task<ResponseActionResult> ApplyFirewallRestrictionAsync(string hostId, FirewallRestriction restriction, CancellationToken ct = default);

    Task<ResponseActionResult> RemoveFirewallRestrictionAsync(string hostId, string ruleName, CancellationToken ct = default);

    Task<ResponseActionResult> DisableServiceAsync(string hostId, string serviceName, CancellationToken ct = default);

    Task<ResponseActionResult> IncreaseTelemetryAsync(string hostId, TimeSpan duration, CancellationToken ct = default);

    /// <summary>Deliberately unimplemented by default (returns Success=false) - credential revocation requires an
    /// organization-specific identity workflow (AD PowerShell, Entra ID Graph, etc.) that must be wired in explicitly
    /// rather than assumed, per doc §17's "authorized identity workflow" requirement.</summary>
    Task<ResponseActionResult> RevokeCredentialAsync(string hostId, string identity, CancellationToken ct = default);
}
