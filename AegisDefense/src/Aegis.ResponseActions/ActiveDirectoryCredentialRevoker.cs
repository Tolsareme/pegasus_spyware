using System.DirectoryServices.AccountManagement;
using Aegis.Core.Diagnostics;
using Aegis.Core.Response;

namespace Aegis.ResponseActions;

/// <summary>
/// Revokes/restores access for a domain identity via <c>System.DirectoryServices.AccountManagement</c>
/// - the "authorized identity workflow" doc §17 calls for. Disables the account and expires
/// its password immediately (forces a password change and blocks new logons using the old
/// credential) rather than deleting or resetting to a random password, so restoration is a
/// one-property flip rather than an unrecoverable action.
///
/// Requires the service account to hold the AD "Reset Password"/"Write Account Restrictions"
/// permission on the target account (or be a Domain Admin) and the host to be domain-joined;
/// on a workgroup machine or without a reachable domain controller, every call fails softly
/// with an explanatory <see cref="ResponseActionResult.Detail"/> rather than throwing out to
/// the caller.
/// </summary>
public sealed class ActiveDirectoryCredentialRevoker : ICredentialRevoker
{
    private readonly IAegisLogger _logger;
    private readonly string? _domainName;

    /// <param name="domainName">Specific domain to bind to, or null to use the joined domain of the local machine.</param>
    public ActiveDirectoryCredentialRevoker(IAegisLogger logger, string? domainName = null)
    {
        _logger = logger;
        _domainName = domainName;
    }

    public Task<ResponseActionResult> RevokeAsync(string identity, CancellationToken ct = default) =>
        Task.Run(() => WithUser(identity, "RevokeCredential", user =>
        {
            user.Enabled = false;
            user.ExpirePasswordNow();
            user.Save();
            return $"Disabled AD account '{identity}' and expired its password immediately.";
        }), ct);

    public Task<ResponseActionResult> RestoreAsync(string identity, CancellationToken ct = default) =>
        Task.Run(() => WithUser(identity, "RestoreCredential", user =>
        {
            user.Enabled = true;
            user.Save();
            return $"Re-enabled AD account '{identity}'. The password remains expired - the user must set a new one at next logon.";
        }), ct);

    private ResponseActionResult WithUser(string identity, string action, Func<UserPrincipal, string> mutate)
    {
        try
        {
            using var context = _domainName is null
                ? new PrincipalContext(ContextType.Domain)
                : new PrincipalContext(ContextType.Domain, _domainName);
            using var user = UserPrincipal.FindByIdentity(context, identity);

            if (user is null)
            {
                var notFound = $"Identity '{identity}' was not found in the domain - nothing to {action.ToLowerInvariant()}.";
                _logger.LogAudit(nameof(ActiveDirectoryCredentialRevoker), action, identity, "NotFound", notFound);
                return new ResponseActionResult { Success = false, Detail = notFound, Reversible = true };
            }

            var detail = mutate(user);
            _logger.LogAudit(nameof(ActiveDirectoryCredentialRevoker), action, identity, "Success", detail);
            return new ResponseActionResult { Success = true, Detail = detail, Reversible = true, RollbackToken = identity };
        }
        catch (PrincipalServerDownException ex)
        {
            var detail = "No domain controller reachable - this host may not be domain-joined, or Active Directory is unavailable. Credential revocation requires a reachable identity provider (doc §17).";
            _logger.Error(nameof(ActiveDirectoryCredentialRevoker), detail, ex);
            return new ResponseActionResult { Success = false, Detail = detail, Reversible = true };
        }
        catch (UnauthorizedAccessException ex)
        {
            var detail = "Access denied - the service account lacks permission to modify this AD object (needs Reset Password / Write Account Restrictions).";
            _logger.Error(nameof(ActiveDirectoryCredentialRevoker), detail, ex);
            return new ResponseActionResult { Success = false, Detail = detail, Reversible = true };
        }
        catch (Exception ex)
        {
            _logger.Error(nameof(ActiveDirectoryCredentialRevoker), $"{action} failed for '{identity}'.", ex);
            return new ResponseActionResult { Success = false, Detail = ex.Message, Reversible = true };
        }
    }
}
