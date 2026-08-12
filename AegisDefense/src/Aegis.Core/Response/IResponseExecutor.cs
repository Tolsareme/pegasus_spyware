using Aegis.Core.Events;

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
/// Identifies one persistence artifact to remove/disable, in exactly the shape the collectors
/// that observe it already produce: <see cref="Kind"/> is the same <see cref="ActionType"/>
/// <c>EventSemantics.IsPersistenceArtifact</c> recognizes, and <see cref="Identifier"/> matches
/// that collector's own <c>ObjectId</c> convention - a service name for
/// <see cref="ActionType.ServiceCreate"/>/<see cref="ActionType.ServiceChange"/>, a scheduled
/// task path for <see cref="ActionType.ScheduledTaskCreate"/>/<see cref="ActionType.ScheduledTaskChange"/>,
/// or <c>"{hive}\{path}\{valueName}"</c> for <see cref="ActionType.RegistrySet"/> (see
/// <c>RegistryPersistenceCollector</c>). This means a triggering <see cref="NormalizedEvent"/>
/// can be turned directly into a removal request with no extra parsing/lookup step.
/// </summary>
public sealed record PersistenceArtifactRef(ActionType Kind, string Identifier);

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

    /// <summary>Disables the identity's authentication capability through the configured identity workflow (doc §17:
    /// "authorized identity workflow"). See <c>Aegis.ResponseActions.ActiveDirectoryCredentialRevoker</c> (v2) for a
    /// real Active Directory implementation; on a non-domain-joined host or when no identity provider is configured
    /// this returns <c>Success=false</c> with an explanatory detail rather than silently no-op'ing.</summary>
    Task<ResponseActionResult> RevokeCredentialAsync(string hostId, string identity, CancellationToken ct = default);

    /// <summary>Reverses <see cref="RevokeCredentialAsync"/> (re-enables the account). Password expiry itself can't
    /// be "undone" - the user still has to set a new password - but access is restored, matching the doc's
    /// reversibility requirement for automated actions wherever the underlying action allows it.</summary>
    Task<ResponseActionResult> RestoreCredentialAsync(string hostId, string identity, CancellationToken ct = default);

    /// <summary>Moves a file believed to be malicious out of place into a locked-down
    /// quarantine location (doc-aligned "bounded, reversible" action - not deletion, so a false
    /// positive is always recoverable via <see cref="RestoreQuarantinedFileAsync"/>). Returns
    /// <see cref="ResponseActionResult.RollbackToken"/> pointing at the quarantined copy.</summary>
    Task<ResponseActionResult> QuarantineFileAsync(string hostId, string filePath, CancellationToken ct = default);

    /// <summary>Reverses <see cref="QuarantineFileAsync"/>, moving the file back to its original location.</summary>
    Task<ResponseActionResult> RestoreQuarantinedFileAsync(string hostId, string quarantineToken, CancellationToken ct = default);

    /// <summary>Disables (never deletes outright - see implementation notes) the persistence
    /// mechanism an attacker used to survive reboot/logoff: a service, a scheduled task, or a
    /// registry run-key value. Deliberately conservative for the same reason
    /// <see cref="DisableServiceAsync"/> disables rather than uninstalls - "the artifact stops
    /// running" is the security-relevant outcome, and stopping short of deletion keeps the
    /// action reversible and keeps forensic evidence intact for later investigation.</summary>
    Task<ResponseActionResult> RemovePersistenceArtifactAsync(string hostId, PersistenceArtifactRef artifact, CancellationToken ct = default);

    /// <summary>Reverses <see cref="RemovePersistenceArtifactAsync"/> using the token it returned.</summary>
    Task<ResponseActionResult> RestorePersistenceArtifactAsync(string hostId, string restoreToken, CancellationToken ct = default);
}
