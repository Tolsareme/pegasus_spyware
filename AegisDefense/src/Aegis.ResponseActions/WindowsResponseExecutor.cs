using System.Diagnostics;
using System.ServiceProcess;
using Aegis.Core.Diagnostics;
using Aegis.Core.Response;

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

    /// <param name="hostId">This machine's identity as known to the fleet (should match the sensor's HostId so audit/graph correlation lines up).</param>
    /// <param name="managementPorts">TCP ports that must remain reachable through an isolation action so the service/GUI/central console can still manage the box (doc §24: "isolate a test endpoint while preserving management connectivity"). Defaults to the Aegis control channel + WinRM (5985/5986) + RDP (3389).</param>
    public WindowsResponseExecutor(string hostId, IAegisLogger logger, int[]? managementPorts = null)
    {
        _hostId = hostId;
        _logger = logger;
        _managementPorts = managementPorts ?? new[] { 5985, 5986, 3389 };
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
        results.Add(await RunNetshAsync($"advfirewall firewall add rule name=\"{ruleName}-out\" dir=out action=block enable=yes", ct));
        results.Add(await RunNetshAsync($"advfirewall firewall add rule name=\"{ruleName}-in\" dir=in action=block enable=yes", ct));

        // ...then punch explicit allow holes for management ports so the box stays controllable.
        if (preserveManagementConnectivity)
        {
            foreach (var port in _managementPorts)
            {
                results.Add(await RunNetshAsync(
                    $"advfirewall firewall add rule name=\"{ruleName}-mgmt-{port}\" dir=in action=allow protocol=TCP localport={port}", ct));
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
            deletions.Add(await RunNetshAsync($"advfirewall firewall delete rule name=\"{ruleName}{suffix}\"", ct));
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
        var args = $"advfirewall firewall add rule name=\"{name}\" dir={restriction.Direction} action={restriction.Action} protocol={restriction.Protocol}" +
                   (restriction.RemoteAddress is not null ? $" remoteip={restriction.RemoteAddress}" : "") +
                   (restriction.RemotePort is not null ? $" remoteport={restriction.RemotePort}" : "");

        var result = await RunNetshAsync(args, ct);
        _logger.LogAudit(nameof(WindowsResponseExecutor), "ApplyFirewallRestriction", hostId, result.Succeeded ? "Success" : "Failure", args);
        return new ResponseActionResult { Success = result.Succeeded, Detail = result.Succeeded ? $"Applied rule '{name}'." : result.Error, Reversible = true, RollbackToken = name };
    }

    public async Task<ResponseActionResult> RemoveFirewallRestrictionAsync(string hostId, string ruleName, CancellationToken ct = default)
    {
        if (!Matches(hostId)) return HostMismatch(hostId, nameof(RemoveFirewallRestrictionAsync));

        var result = await RunNetshAsync($"advfirewall firewall delete rule name=\"{ruleName}\"", ct);
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

            var configResult = await ProcessRunner.RunAsync("sc.exe", $"config \"{serviceName}\" start= disabled", ct: ct).ConfigureAwait(false);
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

    public Task<ResponseActionResult> RevokeCredentialAsync(string hostId, string identity, CancellationToken ct = default)
    {
        const string detail = "Not implemented: credential revocation requires an organization-specific identity workflow (AD PowerShell / Entra ID Graph API) to be configured (doc §17).";
        _logger.LogAudit(nameof(WindowsResponseExecutor), "RevokeCredential", hostId, "NotImplemented", $"identity={identity}");
        return Task.FromResult(new ResponseActionResult { Success = false, Detail = detail, Reversible = true });
    }

    private bool Matches(string hostId) => string.Equals(hostId, _hostId, StringComparison.OrdinalIgnoreCase);

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
