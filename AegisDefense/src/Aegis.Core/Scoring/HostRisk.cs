using Aegis.Core.Events;
using Aegis.Core.Features;
using Aegis.Core.Rules;

using Aegis.Core.Compat;

namespace Aegis.Core.Scoring;

/// <summary>
/// Named components of the composite HostRisk formula from doc §12, each already
/// normalized to [0,1] before weighting, so the GUI's evidence trail can show
/// "why" a host's risk went up without exposing raw internal math.
/// </summary>
public sealed record HostRiskBreakdown
{
    public required string HostId { get; init; }
    public required DateTimeOffset AsOf { get; init; }

    public double ProcessBehavior { get; init; }
    public double IdentityRisk { get; init; }
    public double NetworkRisk { get; init; }
    public double PersistenceRisk { get; init; }
    public double CredentialRisk { get; init; }
    public double LateralMovementRisk { get; init; }
    public double FileBehavior { get; init; }
    public double VulnerabilityContext { get; init; }
    public double MlAnomalyScore { get; init; }
    public double AttackSequenceScore { get; init; }
    public double AutonomyScore { get; init; }
    public required AutonomyScoreComponents AutonomyComponents { get; init; }

    /// <summary>0..100 composite score. &gt;=80 is treated as Critical by the default policy - see <see cref="Aegis.Core.Policy.DefensePolicy"/>.</summary>
    public double Total { get; init; }

    /// <summary>Evidence-quality confidence in [0,1]; low when the window has very few supporting events.</summary>
    public double Confidence { get; init; }

    public required IReadOnlyList<RuleFinding> ContributingFindings { get; init; }
}

/// <summary>Per-component weights for the HostRisk composite (doc §12 "normalize component scores, calibrate them against false-positive cost").</summary>
public sealed class HostRiskWeights
{
    public double ProcessBehavior { get; init; } = 1.0;
    public double IdentityRisk { get; init; } = 1.0;
    public double NetworkRisk { get; init; } = 0.8;
    public double PersistenceRisk { get; init; } = 1.3;
    public double CredentialRisk { get; init; } = 1.3;
    public double LateralMovementRisk { get; init; } = 1.4;
    public double FileBehavior { get; init; } = 1.2;
    public double VulnerabilityContext { get; init; } = 0.7;
    public double MlAnomalyScore { get; init; } = 1.0;
    public double AttackSequenceScore { get; init; } = 1.5;
    public double AutonomyScore { get; init; } = 1.1;

    public static HostRiskWeights Default { get; } = new();
}

/// <summary>
/// Fuses the rule engine, feature snapshot, autonomy score, and two externally-supplied
/// signals (ML anomaly score and vulnerability exposure - both pluggable, doc §8) into the
/// single composite HostRisk used to drive response-level decisions.
/// </summary>
public static class HostRiskCalculator
{
    public static HostRiskBreakdown Compute(
        FeatureSnapshot features,
        IReadOnlyList<RuleFinding> findings,
        double mlAnomalyScore = 0.0,
        double vulnerabilityExposureScore = 0.0,
        double attackSequenceScore = 0.0,
        HostRiskWeights? weights = null)
    {
        weights ??= HostRiskWeights.Default;

        var autonomy = AutonomyScoreCalculator.Compute(features);

        var processBehavior = Clamp01(features.ProcessRarity * 0.6 + features.CommandComplexity * 0.4);
        var identityRisk = Clamp01(
            Normalize(features.AuthFailureCount, 10) * 0.3 +
            Normalize(features.AuthFailureThenSuccessCount, 3) * 0.4 +
            Normalize(features.UnusualLogonTypeCount, 3) * 0.3);
        var networkRisk = Clamp01(Normalize(features.RemoteContactRate, 5) * 0.5 + Normalize(features.NewDestinationCount, 15) * 0.5);
        var persistenceRisk = features.PersistenceAfterExecutionSeconds is not null ? 0.9 : 0.0;
        var credentialRisk = features.CredentialToRemoteAuthSeconds is not null ? 0.85 : 0.0;
        var lateralMovementRisk = Clamp01(
            (features.CredentialToRemoteAuthSeconds is not null ? 0.5 : 0.0) +
            Normalize(features.NewDestinationCount, 10) * 0.5);
        var fileBehavior = Clamp01(Normalize(features.FileWriteBurstCount, 60) * (features.HighEntropyWriteObserved ? 1.0 : 0.6));

        var breakdownSum =
            processBehavior * weights.ProcessBehavior +
            identityRisk * weights.IdentityRisk +
            networkRisk * weights.NetworkRisk +
            persistenceRisk * weights.PersistenceRisk +
            credentialRisk * weights.CredentialRisk +
            lateralMovementRisk * weights.LateralMovementRisk +
            fileBehavior * weights.FileBehavior +
            Clamp01(vulnerabilityExposureScore) * weights.VulnerabilityContext +
            Clamp01(mlAnomalyScore) * weights.MlAnomalyScore +
            Clamp01(attackSequenceScore) * weights.AttackSequenceScore +
            autonomy.Score * weights.AutonomyScore;

        var maxPossible =
            weights.ProcessBehavior + weights.IdentityRisk + weights.NetworkRisk + weights.PersistenceRisk +
            weights.CredentialRisk + weights.LateralMovementRisk + weights.FileBehavior + weights.VulnerabilityContext +
            weights.MlAnomalyScore + weights.AttackSequenceScore + weights.AutonomyScore;

        var total = maxPossible > 0 ? Clamp01(breakdownSum / maxPossible) * 100.0 : 0.0;

        // Confidence grows with supporting event volume and with the number of independent
        // rules agreeing, and is penalized when only a single thin signal is driving the score.
        var evidenceVolumeConfidence = Normalize(features.WindowEventCount, 40);
        var ruleAgreementConfidence = Normalize(findings.Count, 3);
        var confidence = Clamp01(0.4 + evidenceVolumeConfidence * 0.35 + ruleAgreementConfidence * 0.25);

        return new HostRiskBreakdown
        {
            HostId = features.HostId,
            AsOf = features.AsOf,
            ProcessBehavior = processBehavior,
            IdentityRisk = identityRisk,
            NetworkRisk = networkRisk,
            PersistenceRisk = persistenceRisk,
            CredentialRisk = credentialRisk,
            LateralMovementRisk = lateralMovementRisk,
            FileBehavior = fileBehavior,
            VulnerabilityContext = Clamp01(vulnerabilityExposureScore),
            MlAnomalyScore = Clamp01(mlAnomalyScore),
            AttackSequenceScore = Clamp01(attackSequenceScore),
            AutonomyScore = autonomy.Score,
            AutonomyComponents = autonomy.Components,
            Total = total,
            Confidence = confidence,
            ContributingFindings = findings,
        };
    }

    private static double Normalize(double value, double max) => max <= 0 ? 0.0 : MathCompat.Clamp(value / max, 0.0, 1.0);
    private static double Clamp01(double v) => MathCompat.Clamp(v, 0.0, 1.0);
}
