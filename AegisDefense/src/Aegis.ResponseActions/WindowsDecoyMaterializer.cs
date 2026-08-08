using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using Aegis.Core.Deception;
using Aegis.Core.Diagnostics;
using Aegis.Core.Response;

namespace Aegis.ResponseActions;

/// <summary>
/// Creates/removes the real on-disk artifact behind a <see cref="DecoyResourceDefinition"/>, and
/// (best-effort) sets a SACL audit rule on it so touching it fires Security-log event 4663
/// (object access), which <c>SecurityEventLogCollector</c> understands. Deliberately
/// conservative about what it will materialize: <see cref="DecoyType.File"/>,
/// <see cref="DecoyType.Directory"/>, and <see cref="DecoyType.Share"/> are plain filesystem/SMB
/// objects with no security-boundary implications, so they're safe to create unattended.
/// <see cref="DecoyType.ServiceIdentity"/>, <see cref="DecoyType.HoneyCredential"/>, and
/// <see cref="DecoyType.Api"/> would each require creating a real Windows service, a real
/// account, or standing up a real endpoint - each a security-relevant action an operator should
/// take deliberately, not something an automated decision should do on their behalf - so those
/// return <c>Success=false</c> with an explanatory detail instead of silently no-op'ing or,
/// worse, quietly creating a real privileged artifact.
///
/// NOTE: object-access auditing (4663) also requires the host's audit policy to actually enable
/// it (<c>auditpol /set /subcategory:"File System" /success:enable /failure:enable</c>) - this
/// class does not flip that system-wide policy itself (enabling it host-wide is a much bigger,
/// noisier decision than creating one decoy file), so document it as a prerequisite - see
/// docs/OPERATIONS.md.
/// </summary>
public sealed class WindowsDecoyMaterializer : IDecoyMaterializer
{
    private readonly IAegisLogger _logger;

    public WindowsDecoyMaterializer(IAegisLogger logger) => _logger = logger;

    public Task<ResponseActionResult> MaterializeAsync(DecoyResourceDefinition decoy, CancellationToken ct = default)
    {
        try
        {
            return Task.FromResult(decoy.Type switch
            {
                DecoyType.File => MaterializeFile(decoy),
                DecoyType.Directory => MaterializeDirectory(decoy),
                DecoyType.Share => MaterializeShare(decoy),
                _ => NotSupported(decoy),
            });
        }
        catch (Exception ex)
        {
            _logger.Error(nameof(WindowsDecoyMaterializer), $"Failed to materialize decoy '{decoy.Id}'.", ex);
            return Task.FromResult(new ResponseActionResult { Success = false, Detail = $"Materialization failed: {ex.Message}", Reversible = true });
        }
    }

    public Task<ResponseActionResult> RemoveAsync(DecoyResourceDefinition decoy, CancellationToken ct = default)
    {
        try
        {
            switch (decoy.Type)
            {
                case DecoyType.File:
                    if (File.Exists(decoy.Location)) File.Delete(decoy.Location);
                    return Task.FromResult(Ok("File decoy removed."));
                case DecoyType.Directory:
                    if (Directory.Exists(decoy.Location)) Directory.Delete(decoy.Location, recursive: true);
                    return Task.FromResult(Ok("Directory decoy removed."));
                case DecoyType.Share:
                    RemoveShare(ShareNameFromLocation(decoy.Location));
                    return Task.FromResult(Ok("Share decoy removed."));
                default:
                    return Task.FromResult(NotSupported(decoy));
            }
        }
        catch (Exception ex)
        {
            _logger.Error(nameof(WindowsDecoyMaterializer), $"Failed to remove decoy '{decoy.Id}'.", ex);
            return Task.FromResult(new ResponseActionResult { Success = false, Detail = $"Removal failed: {ex.Message}", Reversible = true });
        }
    }

    private ResponseActionResult MaterializeFile(DecoyResourceDefinition decoy)
    {
        var dir = Path.GetDirectoryName(decoy.Location);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        // Deliberately inert placeholder content - never a real secret, matching
        // DecoyResourceDefinition.GrantsRealPrivilege being structurally always false.
        File.WriteAllText(decoy.Location, $"# {decoy.Description}{Environment.NewLine}# Managed by Aegis Defense - do not use or remove.{Environment.NewLine}");

        TryAddAuditRule(decoy.Location, isDirectory: false);
        return Ok($"File decoy created at '{decoy.Location}'.");
    }

    private ResponseActionResult MaterializeDirectory(DecoyResourceDefinition decoy)
    {
        Directory.CreateDirectory(decoy.Location);
        TryAddAuditRule(decoy.Location, isDirectory: true);
        return Ok($"Directory decoy created at '{decoy.Location}'.");
    }

    private ResponseActionResult MaterializeShare(DecoyResourceDefinition decoy)
    {
        // decoy.Location is a UNC path (\\host\ShareName) - the backing folder lives under
        // this host's own temp root and is shared out under that share name.
        var shareName = ShareNameFromLocation(decoy.Location);
        var backingPath = Path.Combine(Path.GetTempPath(), "AegisDecoyShares", shareName);
        Directory.CreateDirectory(backingPath);
        TryAddAuditRule(backingPath, isDirectory: true);

        var (exitCode, error) = RunNet($"share {shareName}=\"{backingPath}\" /grant:Everyone,read");
        if (exitCode != 0)
            return new ResponseActionResult { Success = false, Detail = $"'net share' failed (exit {exitCode}): {error}", Reversible = true };

        return Ok($"Share decoy '{shareName}' created, backed by '{backingPath}'.");
    }

    private void RemoveShare(string shareName) => RunNet($"share {shareName} /delete /y");

    private static (int ExitCode, string Error) RunNet(string arguments)
    {
        var psi = new ProcessStartInfo("net.exe", arguments)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var proc = Process.Start(psi)!;
        var error = proc.StandardError.ReadToEnd();
        proc.WaitForExit(10_000);
        return (proc.ExitCode, error);
    }

    private static string ShareNameFromLocation(string location) =>
        location.TrimStart('\\').Split('\\').Last();

    /// <summary>Best-effort: adds a SACL audit rule so any read/write/delete on the decoy fires
    /// Security-log event 4663, even though this decoy is not "in use" by any legitimate process
    /// or user. Requires the service account to hold SeSecurityPrivilege (LocalSystem has it) and
    /// object-access auditing to be enabled host-wide (see docs/OPERATIONS.md); soft-fails
    /// otherwise since the decoy artifact itself still exists and is still matched by
    /// <see cref="DeceptionManager"/> for whatever telemetry does surface access to it (e.g. a
    /// process-create/file-write collector, or ETW).</summary>
    private void TryAddAuditRule(string path, bool isDirectory)
    {
        try
        {
            var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
            if (isDirectory)
            {
                var security = new DirectorySecurity(path, AccessControlSections.Audit);
                security.AddAuditRule(new FileSystemAuditRule(
                    everyone,
                    FileSystemRights.Read | FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.Traverse,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AuditFlags.Success | AuditFlags.Failure));
                new DirectoryInfo(path).SetAccessControl(security);
            }
            else
            {
                var security = new FileSecurity(path, AccessControlSections.Audit);
                security.AddAuditRule(new FileSystemAuditRule(
                    everyone,
                    FileSystemRights.Read | FileSystemRights.Write | FileSystemRights.Delete,
                    AuditFlags.Success | AuditFlags.Failure));
                new FileInfo(path).SetAccessControl(security);
            }
        }
        catch (Exception ex)
        {
            _logger.Warn(nameof(WindowsDecoyMaterializer),
                $"Could not set an audit rule on decoy '{path}' (object-access auditing may not be enabled, or SeSecurityPrivilege is missing) - the decoy artifact still exists, but 4663 event coverage may be unavailable: {ex.Message}");
        }
    }

    private static ResponseActionResult Ok(string detail) => new() { Success = true, Detail = detail, Reversible = true };

    private static ResponseActionResult NotSupported(DecoyResourceDefinition decoy) => new()
    {
        Success = false,
        Detail = $"Decoy type '{decoy.Type}' is not auto-materialized (it would require creating a real service, account, or endpoint - a deliberate operator action, not an automated one). Register the definition and provision '{decoy.Location}' manually.",
        Reversible = true,
    };
}
