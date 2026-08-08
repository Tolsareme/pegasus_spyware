using System.Diagnostics;
using System.Text;

namespace Aegis.ResponseActions;

internal sealed record ProcessRunResult(int ExitCode, string StdOut, string StdErr)
{
    public bool Succeeded => ExitCode == 0;
}

/// <summary>
/// Runs a local OS tool (netsh, sc.exe) and captures output. Every containment action in
/// this assembly goes through here rather than a raw <see cref="Process.Start()"/> call
/// scattered around, so there is exactly one place that sets a timeout, disables shell
/// execution, and captures stdout/stderr for the audit trail.
/// </summary>
internal static class ProcessRunner
{
    public static async Task<ProcessRunResult> RunAsync(string fileName, string arguments, TimeSpan? timeout = null, CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        using var process = new Process { StartInfo = psi, EnableRaisingEvents = true };
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();

        process.OutputDataReceived += (_, e) => { if (e.Data is not null) stdout.AppendLine(e.Data); };
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) stderr.AppendLine(e.Data); };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout ?? TimeSpan.FromSeconds(30));

        try
        {
#if NET5_0_OR_GREATER
            await process.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
#else
            var effectiveTimeout = timeout ?? TimeSpan.FromSeconds(30);
            var exited = await Task.Run(() => process.WaitForExit((int)effectiveTimeout.TotalMilliseconds), timeoutCts.Token).ConfigureAwait(false);
            if (!exited)
            {
                throw new OperationCanceledException("Process did not exit within the timeout.");
            }
#endif
        }
        catch (OperationCanceledException)
        {
            try { if (!process.HasExited) process.Kill(); } catch { /* best-effort */ }
            throw new TimeoutException($"'{fileName} {arguments}' did not complete within {timeout}.");
        }

        return new ProcessRunResult(process.ExitCode, stdout.ToString(), stderr.ToString());
    }
}
