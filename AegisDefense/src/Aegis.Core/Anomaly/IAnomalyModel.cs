using Aegis.Core.Features;

namespace Aegis.Core.Anomaly;

/// <summary>One feature's contribution to an anomaly score - kept so the GUI's evidence trail can say *why* a host looked anomalous, not just "0.83".</summary>
public sealed record AnomalyFeatureContribution(string Feature, double Value, double Mean, double StdDev, double ZScore);

public sealed record AnomalyScoreResult(double Score, bool IsWarmedUp, IReadOnlyList<AnomalyFeatureContribution> TopContributors);

/// <summary>
/// The pluggable "statistical/ML engine" from doc §8. <see cref="StatisticalAnomalyModel"/>
/// is a real, functional, unsupervised online detector (no training data required - it
/// learns each host's normal as it runs). A heavier trained/offline model (isolation
/// forest, autoencoder, an ONNX Runtime-hosted network) can implement this same interface
/// and be swapped in via <c>DefenseEngine</c>'s constructor without touching the fusion
/// logic in <see cref="Aegis.Core.Scoring.HostRiskCalculator"/>.
/// </summary>
public interface IAnomalyModel
{
    /// <summary>Incorporates one more observation into the host's learned baseline. Call before or after scoring - order doesn't matter for the online estimator, but observe-then-score means the model never scores its own most recent point as anomalous.</summary>
    void Observe(string hostId, FeatureSnapshot features);

    /// <summary>Returns a [0,1] anomaly score plus an explanation. Score is 0 (not "unknown") while the model is still warming up - see <see cref="AnomalyScoreResult.IsWarmedUp"/> to distinguish "definitely normal" from "not enough data yet".</summary>
    AnomalyScoreResult Score(string hostId, FeatureSnapshot features);
}
