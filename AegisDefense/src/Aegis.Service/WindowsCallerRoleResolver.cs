using System.IO.Pipes;
using System.Security.Principal;
using Aegis.Core.Diagnostics;
using Aegis.Core.Policy;

namespace Aegis.Service;

/// <summary>
/// Maps a connected pipe client to an <see cref="OperatorRole"/> via Windows group
/// membership, using the named pipe's built-in client impersonation
/// (<see cref="NamedPipeServerStream.RunAsClient{T}"/>) - the standard, supported way to
/// find out "who is actually on the other end of this connection" without trusting
/// anything the client claims about itself.
///
/// Administrators always map to <see cref="OperatorRole.Administrator"/>. Members of the
/// local group named by <see cref="AnalystGroupName"/> (created by an administrator during
/// provisioning - see docs/OPERATIONS.md) map to <see cref="OperatorRole.Analyst"/>. Anyone
/// else - which given the pipe's ACL should be nobody, since only Administrators and that
/// group can even connect - maps to <see cref="OperatorRole.Unknown"/> and is refused.
/// </summary>
public static class WindowsCallerRoleResolver
{
    public const string AnalystGroupName = "AegisDefense Analysts";

    /// <summary>Returns "{Role}|{WindowsIdentityName}" (e.g. "Administrator|CONTOSO\jdoe") -
    /// <see cref="Aegis.Service.IpcRequestHandler"/> splits this back apart so the resolved,
    /// impersonation-verified Windows identity is available for audit purposes (e.g. WhoAmI),
    /// distinct from whatever a caller might separately claim in a request payload.</summary>
    public static string Resolve(NamedPipeServerStream pipe, IAegisLogger logger)
    {
        try
        {
            var role = OperatorRole.Unknown;
            string? identityName = null;
            pipe.RunAsClient(() =>
            {
                using var identity = WindowsIdentity.GetCurrent();
                identityName = identity.Name;
                var principal = new WindowsPrincipal(identity);

                if (principal.IsInRole(WindowsBuiltInRole.Administrator))
                {
                    role = OperatorRole.Administrator;
                }
                else if (TryIsInGroup(principal, AnalystGroupName))
                {
                    role = OperatorRole.Analyst;
                }
            });
            return $"{role}|{identityName}";
        }
        catch (Exception ex)
        {
            logger.Error(nameof(WindowsCallerRoleResolver), "Failed to resolve caller role via pipe impersonation - treating as Unknown (refused).", ex);
            return OperatorRole.Unknown.ToString();
        }
    }

    private static bool TryIsInGroup(WindowsPrincipal principal, string groupName)
    {
        try
        {
            return principal.IsInRole(groupName);
        }
        catch (Exception)
        {
            // The group doesn't exist on this host (Analyst role not provisioned) - not an error, just "not a member".
            return false;
        }
    }
}
