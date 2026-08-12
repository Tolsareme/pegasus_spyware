using System.Diagnostics;
using System.ServiceProcess;
using System.Text.Json;
using Aegis.Core.Diagnostics;
using Aegis.Core.Events;
using Aegis.Core.Response;
using Microsoft.Win32;

namespace Aegis.ResponseActions;

/// <summary>
/// Local, Windows-native implementation of <see cref="IResponseExecutor"/>. Every action
/// operates only on the machine this process runs on (checked via <see cref="_hostId"/>) -
/// this MVP's response module is per-endpoint, matching the doc §19 architecture diagram
/// ("local response module" living beside the sensor on each Windows Endpoint/Server).
/// Fleet-wide "Enterprise response" (doc §14's top tier) requires a central coordination
/// channel across many of these local executors and is a WP8+ extension, not implemented
/// here - the interface is ready for it.
///
/// Uses only tools/APIs that have shipped unchanged since Windows 7 SP1 / Server 2008 R2
/// (netsh advfirewall, sc.exe, ServiceController, Process) so the same binary behaves
/// identically on the oldest and newest supported OS.
/// </summary>
public sealed class WindowsResponseExecutor : IResponseExecutor
{
    private const string IsolationRulePrefix = "AegisIsolation-";
    private const string RestrictionRulePrefix = "AegisRestrict-";

    private readonly string _hostId;
    private readonly IAegisLogger _logger;
    private readonly int[] _managementPorts;
    private readonly ICredentialRevoker _credentialRevoker;

    /// <param name="hostId">This machine's identity as known to the fleet (should match the sensor's HostId so audit/graph correlation lines up).</param>
    /// <param name="managementPorts">TCP ports that must remain reachable through an isolation action so the service/GUI/central console can still manage the box (doc §24: "isolate a test endpoint while preserving management connectivity"). Defaults to the Aegis control channel + WinRM (5985/5986) + RDP (3389).</param>
    /// <param name="credentialRevoker">Identity-provider integration for RevokeCredentialAsync/RestoreCredentialAsync. Defaults to Active Directory (v2), which fails soft with an explanatory detail on a non-domain-joined host - pass <see cref="NullCredentialRevoker"/> explicitly to disable the attempt entirely, or your own <see cref="ICredentialRevoker"/> for a different identity provider.</param>
    public WindowsResponseExecutor(string hostId, IAegisLogger logger, int[]? managementPorts = null, ICredentialRevoker? credentialRevoker = null)
    {
        _hostId = hostId;
        _logger = logger;
        _managementPorts = managementPorts ?? new[] { 5985, 5986, 3389 };
        _credentialRevoker = credentialRevoker ?? new ActiveDirectoryCredentialRevoker(logger);
    }

    private ResponseActionResult HostMismatch(string hostId, string action)
    {
        var detail = $"Refused: '{action}' targeted host '{hostId}' but this executor is bound to local host '{_hostId}'.";
        _logger.Warn(nameof(WindowsResponseExecutor), detail);
        return new ResponseActionResult { Success = false, Detail = detail, Reversible = true };
    }

    public async Task<ResponseActionResult> IsolateEndpointAsync(string hostId, bool preserveManagementConnectivity, CancellationToken ct = default)
    {
        if (!Matches(hostId)) return HostMismatch(hostId, nameof(IsolateEndpointAsync));

        var ruleName = IsolationRulePrefix + hostId;
        var results = new List<ProcessRunResultSummary>();

        // Block all outbound and inbound traffic under this rule name...
        results.Add(await RunNetshAsync($"advfirewall firewall add rule name={Q(ruleName + "-out")} dir=out action=block enable=yes", ct));
        results.Add(await RunNetshAsync($"advfirewall firewall add rule name={Q(ruleName + "-in")} dir=in action=block enable=yes", ct));

        // ...then punch explicit allow holes for management ports so the box stays controllable.
        if (preserveManagementConnectivity)
        {
            foreach (var port in _managementPorts)
            {
                results.Add(await RunNetshAsync(
                    $"advfirewall firewall add rule name={Q(ruleName + $"-mgmt-{port}")} dir=in action=allow protocol=TCP localport={port}", ct));
            }
        }

        var success = results.All(r => r.Succeeded);
        var detail = success
            ? $"Host isolated (management ports preserved: {preserveManagementConnectivity}). Rule prefix '{ruleName}'."
            : "One or more firewall rule operations failed: " + string.Join(" | ", results.Where(r => !r.Succeeded).Select(r => r.Error));

        _logger.LogAudit(nameof(WindowsResponseExecutor), "IsolateEndpoint", hostId, success ? "Success" : "PartialFailure", detail);
        return new ResponseActionResult { Success = success, Detail = detail, Reversible = true, RollbackToken = ruleName };
    }

    public async Task<ResponseActionResult> ReleaseIsolationAsync(string hostId, CancellationToken ct = default)
    {
        if (!Matches(hostId)) return HostMismatch(hostId, nameof(ReleaseIsolationAsync));

        var ruleName = IsolationRulePrefix + hostId;
        // netsh's name=all form deletes *every* firewall rule on the box, which is never what we
        // want here - delete only the specific named rules this executor created, one at a time.
        var deletions = new List<ProcessRunResultSummary>();
        foreach (var suffix in new[] { "-out", "-in" }.Concat(_managementPorts.Select(p => $"-mgmt-{p}")))
        {
            deletions.Add(await RunNetshAsync($"advfirewall firewall delete rule name={Q(ruleName + suffix)}", ct));
        }

        var success = deletions.All(r => r.Succeeded || r.NotFound);
        var detail = success ? $"Isolation released for '{hostId}'." : "Some isolation rules could not be removed - manual cleanup may be required.";
        _logger.LogAudit(nameof(WindowsResponseExecutor), "ReleaseIsolation", hostId, success ? "Success" : "PartialFailure", detail);
        return new ResponseActionResult { Success = success, Detail = detail, Reversible = true };
    }

    public Task<ResponseActionResult> TerminateProcessAsync(string hostId, int processId, string? expectedImagePath, CancellationToken ct = default)
    {
        if (!Matches(hostId)) return Task.FromResult(HostMismatch(hostId, nameof(TerminateProcessAsync)));

        try
        {
            using var process = Process.GetProcessById(processId);

            // Safety check: refuse to kill a process whose current image doesn't match what the
            // alert evidence expected - protects against PID reuse killing an unrelated process.
            if (expectedImagePath is not null)
            {
                var actualPath = TryGetImagePath(process);
                if (actualPath is not null && !string.Equals(actualPath, expectedImagePath, StringComparison.OrdinalIgnoreCase))
                {
                    var mismatchDetail = $"Refused: PID {processId} is now '{actualPath}', not the expected '{expectedImagePath}' (likely PID reuse).";
                    _logger.LogAudit(nameof(WindowsResponseExecutor), "TerminateProcess", hostId, "Refused", mismatchDetail);
                    return Task.FromResult(new ResponseActionResult { Success = false, Detail = mismatchDetail, Reversible = false });
                }
            }

            process.Kill();
            var detail = $"Terminated PID {processId} ({expectedImagePath ?? "unknown image"}).";
            _logger.LogAudit(nameof(WindowsResponseExecutor), "TerminateProcess", hostId, "Success", detail);
            return Task.FromResult(new ResponseActionResult { Success = true, Detail = detail, Reversible = false });
        }
        catch (ArgumentException)
        {
            var detail = $"PID {processId} was not running - nothing to terminate.";
            return Task.FromResult(new ResponseActionResult { Success = true, Detail = detail, Reversible = false });
        }
        catch (Exception ex)
        {
            _logger.Error(nameof(WindowsResponseExecutor), $"TerminateProcess failed for PID {processId}", ex);
            return Task.FromResult(new ResponseActionResult { Success = false, Detail = ex.Message, Reversible = false });
        }
    }

    public async Task<ResponseActionResult> ApplyFirewallRestrictionAsync(string hostId, FirewallRestriction restriction, CancellationToken ct = default)
    {
        if (!Matches(hostId)) return HostMismatch(hostId, nameof(ApplyFirewallRestrictionAsync));

        var name = RestrictionRulePrefix + restriction.RuleName;
        var args = $"advfirewall firewall add rule name={Q(name)} dir={Q(restriction.Direction)} action={Q(restriction.Action)} protocol={Q(restriction.Protocol)}" +
                   (restriction.RemoteAddress is not null ? $" remoteip={Q(restriction.RemoteAddress)}" : "") +
                   (restriction.RemotePort is not null ? $" remoteport={restriction.RemotePort}" : "");

        var result = await RunNetshAsync(args, ct);
        _logger.LogAudit(nameof(WindowsResponseExecutor), "ApplyFirewallRestriction", hostId, result.Succeeded ? "Success" : "Failure", args);
        return new ResponseActionResult { Success = result.Succeeded, Detail = result.Succeeded ? $"Applied rule '{name}'." : result.Error, Reversible = true, RollbackToken = name };
    }

    public async Task<ResponseActionResult> RemoveFirewallRestrictionAsync(string hostId, string ruleName, CancellationToken ct = default)
    {
        if (!Matches(hostId)) return HostMismatch(hostId, nameof(RemoveFirewallRestrictionAsync));

        var result = await RunNetshAsync($"advfirewall firewall delete rule name={Q(ruleName)}", ct);
        var success = result.Succeeded || result.NotFound;
        _logger.LogAudit(nameof(WindowsResponseExecutor), "RemoveFirewallRestriction", hostId, success ? "Success" : "Failure", ruleName);
        return new ResponseActionResult { Success = success, Detail = success ? $"Removed rule '{ruleName}'." : result.Error, Reversible = true };
    }

    public async Task<ResponseActionResult> DisableServiceAsync(string hostId, string serviceName, CancellationToken ct = default)
    {
        if (!Matches(hostId)) return HostMismatch(hostId, nameof(DisableServiceAsync));

        try
        {
            using (var sc = new ServiceController(serviceName))
            {
                if (sc.Status != ServiceControllerStatus.Stopped)
                {
                    sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                }
            }

            var configResult = await ProcessRunner.RunAsync("sc.exe", $"config {Q(serviceName)} start= disabled", ct: ct).ConfigureAwait(false);
            var success = configResult.Succeeded;
            var detail = success ? $"Service '{serviceName}' stopped and disabled." : $"Stopped '{serviceName}' but failed to set start type disabled: {configResult.StdErr}";
            _logger.LogAudit(nameof(WindowsResponseExecutor), "DisableService", hostId, success ? "Success" : "PartialFailure", detail);
            return new ResponseActionResult { Success = success, Detail = detail, Reversible = true, RollbackToken = serviceName };
        }
        catch (Exception ex)
        {
            _logger.Error(nameof(WindowsResponseExecutor), $"DisableService failed for '{serviceName}'", ex);
            return new ResponseActionResult { Success = false, Detail = ex.Message, Reversible = true };
        }
    }

    public Task<ResponseActionResult> IncreaseTelemetryAsync(string hostId, TimeSpan duration, CancellationToken ct = default)
    {
        if (!Matches(hostId)) return Task.FromResult(HostMismatch(hostId, nameof(IncreaseTelemetryAsync)));

        // The actual verbosity toggle lives in Aegis.Service's telemetry manager (it owns the
        // collectors); this executor only records the decision for audit. The service wires
        // this same call to its own in-process telemetry-level switch.
        var detail = $"Requested elevated telemetry for {duration}.";
        _logger.LogAudit(nameof(WindowsResponseExecutor), "IncreaseTelemetry", hostId, "Success", detail);
        return Task.FromResult(new ResponseActionResult { Success = true, Detail = detail, Reversible = true });
    }

    public async Task<ResponseActionResult> RevokeCredentialAsync(string hostId, string identity, CancellationToken ct = default)
    {
        if (!Matches(hostId)) return HostMismatch(hostId, nameof(RevokeCredentialAsync));
        return await _credentialRevoker.RevokeAsync(identity, ct).ConfigureAwait(false);
    }

    public async Task<ResponseActionResult> RestoreCredentialAsync(string hostId, string identity, CancellationToken ct = default)
    {
        if (!Matches(hostId)) return HostMismatch(hostId, nameof(RestoreCredentialAsync));
        return await _credentialRevoker.RestoreAsync(identity, ct).ConfigureAwait(false);
    }

    public Task<ResponseActionResult> QuarantineFileAsync(string hostId, string filePath, CancellationToken ct = default)
    {
        if (!Matches(hostId)) return Task.FromResult(HostMismatch(hostId, nameof(QuarantineFileAsync)));

        try
        {
            if (!File.Exists(filePath))
                return Task.FromResult(new ResponseActionResult { Success = false, Detail = $"File not found: '{filePath}' (already gone, or a stale/bad path).", Reversible = true });

            var quarantineRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AegisDefense", "quarantine");
            Directory.CreateDirectory(quarantineRoot);

            var quarantinedPath = Path.Combine(quarantineRoot, Guid.NewGuid().ToString("N") + ".quarantined");
            File.Move(filePath, quarantinedPath);
            File.WriteAllText(quarantinedPath + ".meta.json", JsonSerializer.Serialize(new QuarantineMetadata(filePath, DateTimeOffset.UtcNow)));

            // Conservative lockdown: mark read-only rather than rewriting ACLs - keeps this
            // action simple and safe to reverse, at the cost of not being bulletproof against
            // an attacker with write access to the quarantine folder itself (LocalSystem-only
            // by default, matching every other Aegis state directory under %ProgramData%).
            try { File.SetAttributes(quarantinedPath, File.GetAttributes(quarantinedPath) | FileAttributes.ReadOnly); } catch { /* best-effort */ }

            var detail = $"Quarantined '{filePath}'.";
            _logger.LogAudit(nameof(WindowsResponseExecutor), "QuarantineFile", hostId, "Success", detail);
            return Task.FromResult(new ResponseActionResult { Success = true, Detail = detail, Reversible = true, RollbackToken = quarantinedPath });
        }
        catch (Exception ex)
        {
            _logger.Error(nameof(WindowsResponseExecutor), $"QuarantineFile failed for '{filePath}'", ex);
            return Task.FromResult(new ResponseActionResult { Success = false, Detail = ex.Message, Reversible = true });
        }
    }

    public Task<ResponseActionResult> RestoreQuarantinedFileAsync(string hostId, string quarantineToken, CancellationToken ct = default)
    {
        if (!Matches(hostId)) return Task.FromResult(HostMismatch(hostId, nameof(RestoreQuarantinedFileAsync)));

        try
        {
            var metaPath = quarantineToken + ".meta.json";
            if (!File.Exists(quarantineToken) || !File.Exists(metaPath))
                return Task.FromResult(new ResponseActionResult { Success = false, Detail = $"No quarantined file/metadata found for token '{quarantineToken}'.", Reversible = false });

            var meta = JsonSerializer.Deserialize<QuarantineMetadata>(File.ReadAllText(metaPath))!;
            var destDir = Path.GetDirectoryName(meta.OriginalPath);
            if (!string.IsNullOrEmpty(destDir)) Directory.CreateDirectory(destDir);

            try { File.SetAttributes(quarantineToken, File.GetAttributes(quarantineToken) & ~FileAttributes.ReadOnly); } catch { /* best-effort */ }
            File.Move(quarantineToken, meta.OriginalPath);
            File.Delete(metaPath);

            var detail = $"Restored quarantined file to '{meta.OriginalPath}'.";
            _logger.LogAudit(nameof(WindowsResponseExecutor), "RestoreQuarantinedFile", hostId, "Success", detail);
            return Task.FromResult(new ResponseActionResult { Success = true, Detail = detail, Reversible = false });
        }
        catch (Exception ex)
        {
            _logger.Error(nameof(WindowsResponseExecutor), $"RestoreQuarantinedFile failed for token '{quarantineToken}'", ex);
            return Task.FromResult(new ResponseActionResult { Success = false, Detail = ex.Message, Reversible = false });
        }
    }

    public async Task<ResponseActionResult> RemovePersistenceArtifactAsync(string hostId, PersistenceArtifactRef artifact, CancellationToken ct = default)
    {
        if (!Matches(hostId)) return HostMismatch(hostId, nameof(RemovePersistenceArtifactAsync));

        try
        {
            return artifact.Kind switch
            {
                ActionType.ServiceCreate or ActionType.ServiceChange => await DisablePersistenceServiceAsync(hostId, artifact.Identifier, ct).ConfigureAwait(false),
                ActionType.ScheduledTaskCreate or ActionType.ScheduledTaskChange => await DisablePersistenceScheduledTaskAsync(hostId, artifact.Identifier, ct).ConfigureAwait(false),
                ActionType.RegistrySet => DisablePersistenceRegistryValue(hostId, artifact.Identifier),
                _ => new ResponseActionResult { Success = false, Detail = $"'{artifact.Kind}' is not a removable persistence artifact type.", Reversible = true },
            };
        }
        catch (Exception ex)
        {
            _logger.Error(nameof(WindowsResponseExecutor), $"RemovePersistenceArtifact failed for {artifact.Kind}:{artifact.Identifier}", ex);
            return new ResponseActionResult { Success = false, Detail = ex.Message, Reversible = true };
        }
    }

    public async Task<ResponseActionResult> RestorePersistenceArtifactAsync(string hostId, string restoreToken, CancellationToken ct = default)
    {
        if (!Matches(hostId)) return HostMismatch(hostId, nameof(RestorePersistenceArtifactAsync));

        try
        {
            if (restoreToken.StartsWith("schtask:", StringComparison.Ordinal))
            {
                var taskPath = restoreToken.Substring("schtask:".Length);
                var result = await ProcessRunner.RunAsync("schtasks.exe", $"/Change /TN {Q(taskPath)} /ENABLE", ct: ct).ConfigureAwait(false);
                var detail = result.Succeeded ? $"Re-enabled scheduled task '{taskPath}'." : $"Failed to re-enable scheduled task '{taskPath}': {result.StdErr}";
                _logger.LogAudit(nameof(WindowsResponseExecutor), "RestorePersistenceArtifact", hostId, result.Succeeded ? "Success" : "Failure", detail);
                return new ResponseActionResult { Success = result.Succeeded, Detail = detail, Reversible = false };
            }

            if (restoreToken.StartsWith("service-backup:", StringComparison.Ordinal))
                return await RestoreServiceStartType(hostId, restoreToken.Substring("service-backup:".Length)).ConfigureAwait(false);

            if (restoreToken.StartsWith("registry-backup:", StringComparison.Ordinal))
                return RestoreRegistryValue(hostId, restoreToken.Substring("registry-backup:".Length));

            return new ResponseActionResult { Success = false, Detail = $"Unrecognized restore token format: '{restoreToken}'.", Reversible = false };
        }
        catch (Exception ex)
        {
            _logger.Error(nameof(WindowsResponseExecutor), $"RestorePersistenceArtifact failed for token '{restoreToken}'", ex);
            return new ResponseActionResult { Success = false, Detail = ex.Message, Reversible = false };
        }
    }

    private async Task<ResponseActionResult> DisablePersistenceServiceAsync(string hostId, string serviceName, CancellationToken ct)
    {
        var originalStartType = TryReadServiceStartType(serviceName) ?? 3; // 3 = Manual, a safe fallback if the pre-disable read itself fails
        var result = await DisableServiceAsync(hostId, serviceName, ct).ConfigureAwait(false);
        if (!result.Success) return result;

        var backupPath = WriteRemediationBackup("service-backup", new ServiceStartTypeBackup(serviceName, originalStartType));
        return result with { RollbackToken = "service-backup:" + backupPath };
    }

    private async Task<ResponseActionResult> RestoreServiceStartType(string hostId, string backupPath)
    {
        if (!File.Exists(backupPath))
            return new ResponseActionResult { Success = false, Detail = $"No service start-type backup found at '{backupPath}'.", Reversible = false };

        var backup = JsonSerializer.Deserialize<ServiceStartTypeBackup>(File.ReadAllText(backupPath))!;
        var startArg = backup.StartType switch { 2 => "auto", 4 => "disabled", _ => "demand" };

        var configResult = await ProcessRunner.RunAsync("sc.exe", $"config {Q(backup.ServiceName)} start= {startArg}").ConfigureAwait(false);
        var detail = configResult.Succeeded ? $"Restored service '{backup.ServiceName}' start type." : $"Failed to restore service '{backup.ServiceName}': {configResult.StdErr}";
        _logger.LogAudit(nameof(WindowsResponseExecutor), "RestorePersistenceArtifact", hostId, configResult.Succeeded ? "Success" : "Failure", detail);
        if (configResult.Succeeded) File.Delete(backupPath);
        return new ResponseActionResult { Success = configResult.Succeeded, Detail = detail, Reversible = false };
    }

    private async Task<ResponseActionResult> DisablePersistenceScheduledTaskAsync(string hostId, string taskPath, CancellationToken ct)
    {
        var result = await ProcessRunner.RunAsync("schtasks.exe", $"/Change /TN {Q(taskPath)} /DISABLE", ct: ct).ConfigureAwait(false);
        var detail = result.Succeeded ? $"Disabled scheduled task '{taskPath}'." : $"Failed to disable scheduled task '{taskPath}': {result.StdErr}";
        _logger.LogAudit(nameof(WindowsResponseExecutor), "RemovePersistenceArtifact", hostId, result.Succeeded ? "Success" : "Failure", detail);
        return new ResponseActionResult { Success = result.Succeeded, Detail = detail, Reversible = true, RollbackToken = "schtask:" + taskPath };
    }

    /// <summary>Deletes (after backing up) a persistence-registry value - see
    /// <see cref="RegistryValueBackup"/> for the string round-trip caveat on non-REG_SZ kinds.</summary>
    private ResponseActionResult DisablePersistenceRegistryValue(string hostId, string identifier)
    {
        if (!TryParseRegistryIdentifier(identifier, out var hive, out var path, out var valueName))
            return new ResponseActionResult { Success = false, Detail = $"Could not parse registry artifact identifier '{identifier}' (expected '{{Hive}}\\{{Path}}\\{{ValueName}}').", Reversible = true };

        using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
        using var key = baseKey.OpenSubKey(path, writable: true);
        if (key is null)
            return new ResponseActionResult { Success = false, Detail = $"Registry key '{hive}\\{path}' not found - already removed?", Reversible = true };

        var currentValue = key.GetValue(valueName);
        if (currentValue is null)
            return new ResponseActionResult { Success = true, Detail = $"Registry value '{identifier}' already absent - nothing to remove.", Reversible = true };

        var valueKind = key.GetValueKind(valueName);
        var backupPath = WriteRemediationBackup("registry-backup", new RegistryValueBackup(identifier, currentValue.ToString() ?? "", valueKind.ToString()));

        key.DeleteValue(valueName, throwOnMissingValue: false);

        var detail = $"Removed persistence registry value '{identifier}'.";
        _logger.LogAudit(nameof(WindowsResponseExecutor), "RemovePersistenceArtifact", hostId, "Success", detail);
        return new ResponseActionResult { Success = true, Detail = detail, Reversible = true, RollbackToken = "registry-backup:" + backupPath };
    }

    private ResponseActionResult RestoreRegistryValue(string hostId, string backupPath)
    {
        if (!File.Exists(backupPath))
            return new ResponseActionResult { Success = false, Detail = $"No registry-value backup found at '{backupPath}'.", Reversible = false };

        var backup = JsonSerializer.Deserialize<RegistryValueBackup>(File.ReadAllText(backupPath))!;
        if (!TryParseRegistryIdentifier(backup.Identifier, out var hive, out var path, out var valueName))
            return new ResponseActionResult { Success = false, Detail = $"Could not parse backed-up identifier '{backup.Identifier}'.", Reversible = false };

        using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
        using var key = baseKey.CreateSubKey(path, writable: true);
        key.SetValue(valueName, backup.Value, (RegistryValueKind)Enum.Parse(typeof(RegistryValueKind), backup.ValueKind));

        var detail = $"Restored persistence registry value '{backup.Identifier}'.";
        _logger.LogAudit(nameof(WindowsResponseExecutor), "RestorePersistenceArtifact", hostId, "Success", detail);
        File.Delete(backupPath);
        return new ResponseActionResult { Success = true, Detail = detail, Reversible = false };
    }

    /// <summary>Parses "{Hive}\{Path}\{ValueName}" back into its parts - the exact inverse of
    /// RegistryPersistenceCollector's own <c>$@"{hive}\{path}\{valueName}"</c> ObjectId format.</summary>
    private static bool TryParseRegistryIdentifier(string identifier, out RegistryHive hive, out string path, out string valueName)
    {
        hive = default;
        path = "";
        valueName = "";

        var firstSep = identifier.IndexOf('\\');
        var lastSep = identifier.LastIndexOf('\\');
        if (firstSep < 0 || lastSep <= firstSep) return false;

        if (!Enum.TryParse(identifier.Substring(0, firstSep), ignoreCase: true, out hive)) return false;

        path = identifier.Substring(firstSep + 1, lastSep - firstSep - 1);
        valueName = identifier.Substring(lastSep + 1);
        return path.Length > 0 && valueName.Length > 0;
    }

    /// <summary>ServiceController exposes no start-type property, so this reads it straight from
    /// the registry (2=Auto, 3=Manual, 4=Disabled) before DisableServiceAsync overwrites it.</summary>
    private static int? TryReadServiceStartType(string serviceName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}");
            return key?.GetValue("Start") as int?;
        }
        catch
        {
            return null;
        }
    }

    private static string WriteRemediationBackup<T>(string kind, T backup)
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AegisDefense", "remediation-backups");
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, $"{kind}-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, JsonSerializer.Serialize(backup));
        return path;
    }

    private bool Matches(string hostId) => string.Equals(hostId, _hostId, StringComparison.OrdinalIgnoreCase);

    /// <summary>Shorthand for <see cref="ArgumentEscaping.Quote"/> - every value interpolated into
    /// a netsh/sc.exe command line in this class goes through this so an embedded space or
    /// double-quote can never terminate a token early and inject additional switches.</summary>
    private static string Q(string value) => ArgumentEscaping.Quote(value);

    private static string? TryGetImagePath(Process process)
    {
        try { return process.MainModule?.FileName; }
        catch { return null; } // access denied / process exited mid-check - fail safe by treating as "unknown", handled by caller
    }

    private async Task<ProcessRunResultSummary> RunNetshAsync(string arguments, CancellationToken ct)
    {
        try
        {
            var result = await ProcessRunner.RunAsync("netsh.exe", arguments, ct: ct).ConfigureAwait(false);
            var notFound = result.StdOut.IndexOf("No rules match", StringComparison.OrdinalIgnoreCase) >= 0;
            return new ProcessRunResultSummary(result.Succeeded, notFound, result.StdErr.Length > 0 ? result.StdErr : result.StdOut);
        }
        catch (Exception ex)
        {
            return new ProcessRunResultSummary(false, false, ex.Message);
        }
    }

    private readonly record struct ProcessRunResultSummary(bool Succeeded, bool NotFound, string Error);
}
