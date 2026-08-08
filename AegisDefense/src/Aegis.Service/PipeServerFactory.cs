using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using Aegis.Ipc;

namespace Aegis.Service;

/// <summary>
/// Builds each new server pipe instance with an explicit ACL: only LocalSystem (the
/// service's own account) and members of the local Administrators group may connect.
/// Aegis.Ipc itself has no Windows ACL dependency (see its comments) - this is the one
/// place that ACL lives, kept in the Windows-only host project.
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
}
