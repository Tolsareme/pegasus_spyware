using Aegis.Core.Compat;
using Aegis.Core.Events;
using Aegis.Core.Rules;

namespace Aegis.Core.Estimation;

/// <summary>
/// One host's belief distribution over attacker objectives at a point in time
/// (doc §10: "maintain hypotheses about the actor's current objective" rather than a
/// single malware probability).
/// </summary>
public sealed record AttackStateSnapshot
{
    public required string HostId { get; init; }
    public required DateTimeOffset AsOf { get; init; }
    public required IReadOnlyDictionary<AttackState, double> Distribution { get; init; }
    public required AttackState CurrentState { get; init; }
    public required double Confidence { get; init; }
    public required IReadOnlyList<(AttackState State, double Probability)> PredictedNext { get; init; }
}

/// <summary>
/// Maintains a decaying, evidence-weighted belief distribution over <see cref="AttackState"/>
/// per host, fed by rule findings (each carrying a StateHint + confidence). This is a
/// transparent, explainable Bayesian-flavored estimator, not a black-box classifier -
/// every number it produces traces back to specific rule findings shown in the alert's
/// evidence trail. WP4 ("Sequence Detection") is expected to add a learned sequence model
/// alongside this one, fused rather than replacing it (doc §8 "no single detector should
/// decide the full incident").
/// </summary>
public sealed class AttackStateEstimator
{
    private sealed class HostState
    {
        public readonly Dictionary<AttackState, double> Scores = new();
        public DateTimeOffset LastUpdate;
    }

    private readonly Dictionary<string, HostState> _hosts = new(StringComparer.OrdinalIgnoreCase);
    private readonly TimeSpan _halfLife;

    /// <summary>Read-only snapshot of each known host's current dominant state, without applying decay or requiring new evidence - used by dashboards/statistics.</summary>
    public IReadOnlyDictionary<string, AttackState> GetCurrentStates()
    {
        var result = new Dictionary<string, AttackState>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in _hosts)
        {
            if (kv.Value.Scores.Count == 0) continue;
            result[kv.Key] = kv.Value.Scores.MaxBy(s => s.Value).Key;
        }
        return result;
    }

    public AttackStateEstimator(TimeSpan? halfLife = null)
    {
        _halfLife = halfLife ?? TimeSpan.FromMinutes(20);
    }

    public AttackStateSnapshot Update(string hostId, DateTimeOffset now, IReadOnlyList<RuleFinding> findings)
    {
        if (!_hosts.TryGetValue(hostId, out var state))
        {
            state = new HostState { LastUpdate = now };
            _hosts[hostId] = state;
        }

        Decay(state, now);

        foreach (var finding in findings)
        {
            if (finding.StateHint == AttackState.Benign) continue;
            var weight = SeverityWeight(finding.Severity) * finding.Confidence;
            state.Scores.TryGetValue(finding.StateHint, out var existing);
            state.Scores[finding.StateHint] = existing + weight;
        }

        state.LastUpdate = now;

        var distribution = Normalize(state.Scores);
        var current = distribution.Count == 0
            ? AttackState.Benign
            : distribution.MaxBy(kv => kv.Value).Key;
        var confidence = distribution.Count == 0 ? 0.0 : distribution[current];
        var predicted = NextObjectivePredictor.Predict(current, distribution);

        return new AttackStateSnapshot
        {
            HostId = hostId,
            AsOf = now,
            Distribution = distribution,
            CurrentState = confidence > 0 ? current : AttackState.Benign,
            Confidence = confidence,
            PredictedNext = predicted,
        };
    }

    private void Decay(HostState state, DateTimeOffset now)
    {
        var elapsed = now - state.LastUpdate;
        if (elapsed <= TimeSpan.Zero || state.Scores.Count == 0) return;

        var decayFactor = Math.Pow(0.5, elapsed.TotalMinutes / _halfLife.TotalMinutes);
        var keys = state.Scores.Keys.ToList();
        foreach (var key in keys)
        {
            var decayed = state.Scores[key] * decayFactor;
            if (decayed < 0.01) state.Scores.Remove(key);
            else state.Scores[key] = decayed;
        }
    }

    private static double SeverityWeight(AlertSeverity severity) => severity switch
    {
        AlertSeverity.Critical => 4.0,
        AlertSeverity.High => 3.0,
        AlertSeverity.Medium => 2.0,
        AlertSeverity.Low => 1.0,
        _ => 0.5,
    };

    private static IReadOnlyDictionary<AttackState, double> Normalize(Dictionary<AttackState, double> scores)
    {
        if (scores.Count == 0) return new Dictionary<AttackState, double>();
        var sum = scores.Values.Sum();
        if (sum <= 0) return new Dictionary<AttackState, double>();
        return scores.ToDictionary(kv => kv.Key, kv => kv.Value / sum);
    }
}
