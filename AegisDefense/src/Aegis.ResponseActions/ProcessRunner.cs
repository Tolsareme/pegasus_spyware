using System.Diagnostics;
using System.Text;

namespace Aegis.ResponseActions;

internal sealed record ProcessRunResult(int ExitCode, string StdOut, string StdErr)
{
    public bool Succeeded => ExitCode == 0;
}

/// <summary>
/// Escapes a value for safe inclusion in a Win32 process command line (the single string
/// <see cref="ProcessStartInfo.Arguments"/> becomes before the child process re-parses it,
/// following the same quoting rules as <c>CommandLineToArgvW</c>, which netsh/sc.exe's own
/// argument parsing also follows). Every value interpolated into a netsh/sc.exe command line
/// in this assembly should go through <see cref="Quote"/> so an embedded space or double-quote
/// character can never terminate a token early and inject additional switches - even though
/// today's call sites mostly pass internally-generated values (rule name prefixes, GUIDs), any
/// value that ultimately traces back to policy/telemetry data (a destination IP, a service
/// name) should not rely on that staying true forever.
/// </summary>
internal static class ArgumentEscaping
{
    public static string Quote(string value)
    {
        if (value.Length > 0 && value.IndexOfAny(new[] { ' ', '"', '\t' }) < 0)
            return value;

        var sb = new StringBuilder();
        sb.Append('"');
        var backslashes = 0;
        foreach (var c in value)
        {
            if (c == '\\')
            {
                backslashes++;
                continue;
            }
            if (c == '"')
            {
                sb.Append('\\', backslashes * 2 + 1).Append('"');
                backslashes = 0;
                continue;
            }
            sb.Append('\\', backslashes);
            backslashes = 0;
            sb.Append(c);
        }
        sb.Append('\\', backslashes * 2).Append('"');
        return sb.ToString();
    }
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
