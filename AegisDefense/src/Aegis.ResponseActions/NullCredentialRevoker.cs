using Aegis.Core.Response;

namespace Aegis.ResponseActions;

/// <summary>Used when no identity-provider integration is configured - explains why nothing happened instead of throwing or silently no-op'ing, so the alert/audit trail is honest about it.</summary>
public sealed class NullCredentialRevoker : ICredentialRevoker
{
    public Task<ResponseActionResult> RevokeAsync(string identity, CancellationToken ct = default) =>
        Task.FromResult(new ResponseActionResult
        {
            Success = false,
            Detail = "No identity-provider integration is configured on this host (see docs/OPERATIONS.md - Active Directory revocation requires domain membership; other providers require their own integration).",
            Reversible = true,
        });

    public Task<ResponseActionResult> RestoreAsync(string identity, CancellationToken ct = default) =>
        Task.FromResult(new ResponseActionResult { Success = false, Detail = "No identity-provider integration is configured on this host.", Reversible = true });
}
