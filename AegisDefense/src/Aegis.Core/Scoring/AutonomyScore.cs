using Aegis.Core.Features;

using Aegis.Core.Compat;

namespace Aegis.Core.Scoring;

/// <summary>
/// Weights for each AutonomyScore component (doc §11). Exposed as a plain settable class
/// so the signed policy file can carry calibrated weights without a code change -
/// "weights and thresholds should be learned and calibrated from controlled experiments".
/// </summary>
public sealed class AutonomyScoreWeights
{
    public double ActionFrequency { get; init; } = 0.15;
    public double TechniqueSwitchingRate { get; init; } = 0.20;
    public double FailureAdaptationRate { get; init; } = 0.20;
    public double ReconnaissanceDepth { get; init; } = 0.15;
    public double TargetSelectionChangeRate { get; init; } = 0.10;
    public double CrossHostCoordination { get; init; } = 0.10;
    public double ResultToNextActionLatency { get; init; } = 0.10;

    public static AutonomyScoreWeights Default { get; } = new();
}

/// <summary>Normalized [0,1] value of every AutonomyScore input, kept alongside the final score for the evidence trail.</summary>
public sealed record AutonomyScoreComponents
{
    public double ActionFrequency { get; init; }
    public double TechniqueSwitchingRate { get; init; }
    public double FailureAdaptationRate { get; init; }
    public double ReconnaissanceDepth { get; init; }
    public double TargetSelectionChangeRate { get; init; }
    public double CrossHostCoordination { get; init; }
    public double ResultToNextActionLatency { get; init; }
}

public sealed record AutonomyScoreResult(double Score, AutonomyScoreComponents Components);

/// <summary>
/// "An AutonomyScore should be treated as a behavioral risk feature, not proof that an AI
/// is responsible... The score should never be the sole reason for destructive remediation"
/// (doc §11). This calculator produces exactly that: a bounded [0,1] behavioral-adaptation
/// signal, never an attribution claim, and callers (HostRiskCalculator, ResponsePolicyEngine)
/// must combine it with other evidence before any high-impact action.
/// </summary>
public static class AutonomyScoreCalculator
{
    public static AutonomyScoreResult Compute(FeatureSnapshot features, AutonomyScoreWeights? weights = null)
    {
        weights ??= AutonomyScoreWeights.Default;

        var actionFrequency = Normalize(features.WindowEventCount, max: 300);
        var techniqueSwitching = Normalize(features.TechniqueSwitchAfterFailureCount, max: 5);
        var failureAdaptation = Normalize(features.TechniqueSwitchAfterFailureCount + features.AuthFailureThenSuccessCount, max: 6);
        var reconDepth = Normalize(features.NewDestinationCount, max: 15) * 0.6 + Normalize(features.RemoteContactRate, max: 5) * 0.4;
        var targetChangeRate = features.WindowEventCount == 0
            ? 0.0
            : Normalize((double)features.NewDestinationCount / features.WindowEventCount, max: 0.5);
        var crossHost = Normalize(features.CrossHostSimilarHostCount, max: 5);
        var latency = LatencyScore(features);

        var components = new AutonomyScoreComponents
        {
            ActionFrequency = actionFrequency,
            TechniqueSwitchingRate = techniqueSwitching,
            FailureAdaptationRate = failureAdaptation,
            ReconnaissanceDepth = reconDepth,
            TargetSelectionChangeRate = targetChangeRate,
            CrossHostCoordination = crossHost,
            ResultToNextActionLatency = latency,
        };

        var score =
            components.ActionFrequency * weights.ActionFrequency +
            components.TechniqueSwitchingRate * weights.TechniqueSwitchingRate +
            components.FailureAdaptationRate * weights.FailureAdaptationRate +
            components.ReconnaissanceDepth * weights.ReconnaissanceDepth +
            components.TargetSelectionChangeRate * weights.TargetSelectionChangeRate +
            components.CrossHostCoordination * weights.CrossHostCoordination +
            components.ResultToNextActionLatency * weights.ResultToNextActionLatency;

        var weightSum = weights.ActionFrequency + weights.TechniqueSwitchingRate + weights.FailureAdaptationRate +
                         weights.ReconnaissanceDepth + weights.TargetSelectionChangeRate + weights.CrossHostCoordination +
                         weights.ResultToNextActionLatency;

        var normalizedScore = weightSum > 0 ? score / weightSum : 0.0;
        return new AutonomyScoreResult(MathCompat.Clamp(normalizedScore, 0.0, 1.0), components);
    }

    /// <summary>Faster observed result-&gt;next-action latency implies a higher (more machine-speed) score.</summary>
    private static double LatencyScore(FeatureSnapshot f)
    {
        var samples = new List<double>();
        if (f.ReconToActionSeconds is { } a) samples.Add(a);
        if (f.CredentialToRemoteAuthSeconds is { } b) samples.Add(b);
        if (f.PersistenceAfterExecutionSeconds is { } c) samples.Add(c);
        if (samples.Count == 0) return 0.0;

        var fastest = samples.Min();
        // 0s -> 1.0 (instantaneous, very machine-like), 300s (5 min) -> ~0, linear in between.
        return MathCompat.Clamp(1.0 - fastest / 300.0, 0.0, 1.0);
    }

    private static double Normalize(double value, double max) =>
        max <= 0 ? 0.0 : MathCompat.Clamp(value / max, 0.0, 1.0);
}
