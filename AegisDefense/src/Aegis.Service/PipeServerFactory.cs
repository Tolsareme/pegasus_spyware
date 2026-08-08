using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using Aegis.Ipc;

namespace Aegis.Service;

/// <summary>
/// Builds each new server pipe instance with an explicit ACL: LocalSystem (the service's own
/// account), members of the local Administrators group, and - if provisioned (v2 RBAC) -
/// members of the "AegisDefense Analysts" local group may connect. The pipe ACL only ever
/// controls who can connect at all; it has no concept of read-only, so Analyst accounts get
/// the same ReadWrite pipe rights as Administrators here and <c>IpcRequestHandler</c> is what
/// actually enforces that an Analyst-role caller can't invoke a mutating message type - see
/// <see cref="WindowsCallerRoleResolver"/>. Aegis.Ipc itself has no Windows ACL dependency
/// (see its comments) - this is the one place that ACL lives, kept in the Windows-only host
/// project.
/// </summary>
internal static class PipeServerFactory
{
    public static NamedPipeServerStream CreateSecured()
    {
        var security = new PipeSecurity();

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.ReadWrite, AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));

        TryAllowAnalystGroup(security);

        // Explicit deny for Everyone/Authenticated Users is unnecessary - PipeSecurity is
        // deny-by-default for anything not explicitly allowed - but stated here for clarity
        // to future maintainers: no other principal should ever be added to this ACL.

        // .NET Framework's NamedPipeServerStream still has the classic PipeSecurity-accepting
        // constructor directly (unlike modern .NET, which moved it to the separate
        // NamedPipeServerStreamAcl.Create helper in System.IO.Pipes.AccessControl).
        return new NamedPipeServerStream(
            PipeConstants.PipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: 4096,
            outBufferSize: 4096,
            pipeSecurity: security);
    }

    /// <summary>The "AegisDefense Analysts" local group is optional - most single-host deployments never create it, so a lookup failure (group doesn't exist) is expected and silently skipped, not an error.</summary>
    private static void TryAllowAnalystGroup(PipeSecurity security)
    {
        try
        {
            var analystAccount = new NTAccount(WindowsCallerRoleResolver.AnalystGroupName);
            var analystSid = (SecurityIdentifier)analystAccount.Translate(typeof(SecurityIdentifier));
            security.AddAccessRule(new PipeAccessRule(analystSid, PipeAccessRights.ReadWrite, AccessControlType.Allow));
        }
        catch (IdentityNotMappedException)
        {
            // Group not provisioned on this host - fine, only Administrators can connect.
        }
    }
}
