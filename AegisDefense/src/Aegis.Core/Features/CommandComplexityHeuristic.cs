using System.Text.RegularExpressions;

using Aegis.Core.Compat;

namespace Aegis.Core.Features;

/// <summary>
/// Cheap, explainable stand-in for real obfuscation/complexity detection (AMSI content
/// inspection is the authoritative source in production - doc §5/§7 "PowerShell / AMSI").
/// Deliberately simple regexes so behavior is predictable and testable; not a replacement
/// for AMSI or a trained classifier.
/// </summary>
public static class CommandComplexityHeuristic
{
    private static readonly Regex[] Indicators =
    {
        new(@"-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{40,}", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"FromBase64String", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"IEX\s*\(|Invoke-Expression", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\[char\]\s*\d+|-join\s*\(", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"Reflection\.Assembly|VirtualAlloc|memcpy|Marshal\.Copy", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"bypass|-nop\b|-w(indowstyle)?\s+hidden|-noni", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\$\{?[a-z0-9]{1,3}\}?\s*=\s*\$\{?[a-z0-9]{1,3}\}?\s*\+", RegexOptions.IgnoreCase | RegexOptions.Compiled),
    };

    /// <summary>Returns a score in [0,1]: fraction of indicators matched, weighted slightly by raw length.</summary>
    public static double Score(string? commandLine)
    {
        if (commandLine is null || commandLine.Trim().Length == 0) return 0.0;

        var hits = 0;
        foreach (var rx in Indicators)
        {
            if (rx.IsMatch(commandLine)) hits++;
        }

        var indicatorScore = (double)hits / Indicators.Length;
        var lengthScore = MathCompat.Clamp(commandLine.Length / 2000.0, 0.0, 1.0) * 0.15;
        return MathCompat.Clamp(indicatorScore * 0.85 + lengthScore, 0.0, 1.0);
    }
}
