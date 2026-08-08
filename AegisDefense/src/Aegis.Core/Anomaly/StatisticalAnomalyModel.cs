using Aegis.Core.Features;

namespace Aegis.Core.Anomaly;

/// <summary>
/// Per-host, per-feature online anomaly detector. Maintains a <see cref="WelfordAccumulator"/>
/// per numeric <see cref="FeatureSnapshot"/> field per host, combines the individual
/// z-scores into one [0,1] score via RMS + a squashing function, and reports the top
/// contributing features for explainability. This is a legitimate, functional unsupervised
/// baseline (doc §8's "statistical/ML engine ... finds previously unseen deviations") - it
/// needs no labeled dataset, only needs to run for a while to learn what's normal per host.
/// It deliberately treats correlated features independently (a diagonal model, not full
/// covariance/Mahalanobis) because with only a few hundred observations per host a full
/// covariance matrix is unstable to invert; WP2/WP4's trained model is the natural
/// upgrade once enough real fleet data exists to fit one properly.
/// </summary>
public sealed class StatisticalAnomalyModel : IAnomalyModel
{
    private sealed class HostModel
    {
        public readonly Dictionary<string, WelfordAccumulator> Features = new(StringComparer.Ordinal);
    }

    private readonly Dictionary<string, HostModel> _hosts = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();
    private readonly long _minSamples;

    public StatisticalAnomalyModel(long minSamplesBeforeScoring = 20)
    {
        _minSamples = minSamplesBeforeScoring;
    }

    public void Observe(string hostId, FeatureSnapshot features)
    {
        lock (_lock)
        {
            var model = GetOrCreate(hostId);
            foreach (var (name, value) in Extract(features))
            {
                GetAccumulator(model, name).Add(value);
            }
        }
    }

    public AnomalyScoreResult Score(string hostId, FeatureSnapshot features)
    {
        lock (_lock)
        {
            if (!_hosts.TryGetValue(hostId, out var model))
            {
                return new AnomalyScoreResult(0.0, false, Array.Empty<AnomalyFeatureContribution>());
            }

            var contributions = new List<AnomalyFeatureContribution>();
            var warmedUp = false;

            foreach (var (name, value) in Extract(features))
            {
                if (!model.Features.TryGetValue(name, out var acc)) continue;
                if (acc.Count >= _minSamples) warmedUp = true;

                var z = acc.ZScore(value, _minSamples);
                contributions.Add(new AnomalyFeatureContribution(name, value, acc.Mean, acc.StdDev, z));
            }

            if (!warmedUp)
            {
                return new AnomalyScoreResult(0.0, false, Array.Empty<AnomalyFeatureContribution>());
            }

            // RMS of per-feature z-scores, squashed into [0,1]. RMS (rather than max) means one
            // mildly-unusual feature doesn't trip the score, but several moderately unusual
            // features together do - matching how real attacker behavior tends to look "a bit
            // off" across many signals rather than extreme in exactly one.
            var meanSquare = contributions.Count == 0 ? 0.0 : contributions.Average(c => c.ZScore * c.ZScore);
            var rms = Math.Sqrt(meanSquare);
            var score = 1.0 - Math.Exp(-rms / 3.0);

            var topContributors = contributions
                .OrderByDescending(c => c.ZScore)
                .Take(5)
                .Where(c => c.ZScore > 0.5)
                .ToList();

            return new AnomalyScoreResult(Math.Min(1.0, score), true, topContributors);
        }
    }

    private HostModel GetOrCreate(string hostId)
    {
        if (!_hosts.TryGetValue(hostId, out var model))
        {
            model = new HostModel();
            _hosts[hostId] = model;
        }
        return model;
    }

    private static WelfordAccumulator GetAccumulator(HostModel model, string feature)
    {
        if (!model.Features.TryGetValue(feature, out var acc))
        {
            acc = new WelfordAccumulator();
            model.Features[feature] = acc;
        }
        return acc;
    }

    /// <summary>The numeric subset of FeatureSnapshot worth baselining. Deliberately excludes fields that are already booleans/rare-event markers (e.g. HighEntropyWriteObserved) - those are better handled by explicit rules than by z-scoring.</summary>
    private static IEnumerable<(string Name, double Value)> Extract(FeatureSnapshot f)
    {
        yield return (nameof(f.ProcessRarity), f.ProcessRarity);
        yield return (nameof(f.CommandComplexity), f.CommandComplexity);
        yield return (nameof(f.AuthFailureCount), f.AuthFailureCount);
        yield return (nameof(f.AuthFailureThenSuccessCount), f.AuthFailureThenSuccessCount);
        yield return (nameof(f.UnusualLogonTypeCount), f.UnusualLogonTypeCount);
        yield return (nameof(f.RemoteContactRate), f.RemoteContactRate);
        yield return (nameof(f.NewDestinationCount), f.NewDestinationCount);
        yield return (nameof(f.PrivilegeChangeCount), f.PrivilegeChangeCount);
        yield return (nameof(f.TechniqueSwitchAfterFailureCount), f.TechniqueSwitchAfterFailureCount);
        yield return (nameof(f.WindowEventCount), f.WindowEventCount);
        yield return (nameof(f.FileWriteBurstCount), f.FileWriteBurstCount);
    }
}
