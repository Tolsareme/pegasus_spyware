using Aegis.Core.Response;

namespace Aegis.ResponseActions;

/// <summary>
/// The actual identity-provider integration behind <see cref="IResponseExecutor.RevokeCredentialAsync"/>.
/// Split out from <see cref="WindowsResponseExecutor"/> so a different identity backend
/// (Entra ID Graph API, a third-party IdP) can be substituted without touching the rest of
/// the response-action wiring - just implement this interface and pass it to
/// <see cref="WindowsResponseExecutor"/>'s constructor.
/// </summary>
public interface ICredentialRevoker
{
    Task<ResponseActionResult> RevokeAsync(string identity, CancellationToken ct = default);

    Task<ResponseActionResult> RestoreAsync(string identity, CancellationToken ct = default);
}
