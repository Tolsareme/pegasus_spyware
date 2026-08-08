namespace Aegis.Core.Compat;

/// <summary>
/// <c>System.Math.Clamp(double, double, double)</c> only exists on netstandard2.1+/
/// net5+ - not on netstandard2.0 or .NET Framework 4.8, both of which this solution must
/// build against so the Windows-old-and-new/Server host projects can reference
/// <c>Aegis.Core</c>. Used everywhere instead of <c>Math.Clamp</c> so the same source
/// compiles unmodified on every target framework in the solution.
/// </summary>
internal static class MathCompat
{
    public static double Clamp(double value, double min, double max)
    {
        if (min > max) throw new ArgumentException($"min ({min}) must be <= max ({max}).");
        if (value < min) return min;
        if (value > max) return max;
        return value;
    }
}
