namespace Aegis.Core.Anomaly;

/// <summary>
/// Welford's single-pass streaming mean/variance algorithm - numerically stable, O(1)
/// memory and time per observation, no need to store history. This is what lets
/// <see cref="StatisticalAnomalyModel"/> "learn" a host's normal behavior forever without
/// ever re-scanning old events.
/// </summary>
public sealed class WelfordAccumulator
{
    public long Count { get; private set; }
    public double Mean { get; private set; }
    private double _m2;

    public double Variance => Count < 2 ? 0.0 : _m2 / (Count - 1);
    public double StdDev => Math.Sqrt(Variance);

    public void Add(double value)
    {
        Count++;
        var delta = value - Mean;
        Mean += delta / Count;
        var delta2 = value - Mean;
        _m2 += delta * delta2;
    }

    /// <summary>Robust z-score: 0 while there isn't enough history to trust the estimate, and clamped so one wild outlier can't single-handedly dominate a combined score.</summary>
    public double ZScore(double value, long minSamples = 20, double clamp = 6.0)
    {
        if (Count < minSamples) return 0.0;
        var stdDev = StdDev;
        if (stdDev < 1e-9) return value == Mean ? 0.0 : clamp; // effectively-constant feature that just changed is maximally surprising
        var z = Math.Abs(value - Mean) / stdDev;
        return Math.Min(z, clamp);
    }
}
