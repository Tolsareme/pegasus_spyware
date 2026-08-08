using Aegis.Core.Estimation;
using Aegis.Core.Events;
using Aegis.Core.Rules;
using Xunit;

namespace Aegis.Tests;

public class AttackStateEstimatorTests
{
    private static RuleFinding Finding(AttackState state, AlertSeverity severity, double confidence = 0.8) => new()
    {
        RuleId = "TEST",
        Name = "test",
        Description = "test",
        Severity = severity,
        StateHint = state,
        Confidence = confidence,
        TriggeringEventId = Guid.NewGuid(),
    };

    [Fact]
    public void Update_WithNoFindings_StaysBenign()
    {
        var estimator = new AttackStateEstimator();
        var snapshot = estimator.Update("host-1", DateTimeOffset.UtcNow, Array.Empty<RuleFinding>());

        Assert.Equal(AttackState.Benign, snapshot.CurrentState);
        Assert.Equal(0.0, snapshot.Confidence);
    }

    [Fact]
    public void Update_PicksDominantState_WhenOneFindingClearlyStronger()
    {
        var estimator = new AttackStateEstimator();
        var now = DateTimeOffset.UtcNow;

        var snapshot = estimator.Update("host-1", now, new[]
        {
            Finding(AttackState.Discovery, AlertSeverity.Low, 0.4),
            Finding(AttackState.CredentialAccess, AlertSeverity.Critical, 0.9),
        });

        Assert.Equal(AttackState.CredentialAccess, snapshot.CurrentState);
    }

    [Fact]
    public void Update_Decays_OlderEvidence_UntilItStopsDominating()
    {
        var estimator = new AttackStateEstimator(halfLife: TimeSpan.FromMinutes(10));
        var t0 = DateTimeOffset.UtcNow;

        estimator.Update("host-1", t0, new[] { Finding(AttackState.Discovery, AlertSeverity.Critical) });

        // 100 minutes later (10 half-lives, ~1/1000 remaining) with no new evidence at all -
        // the old Discovery finding should have decayed away entirely rather than lingering forever.
        var snapshot = estimator.Update("host-1", t0.AddMinutes(100), Array.Empty<RuleFinding>());

        Assert.Equal(AttackState.Benign, snapshot.CurrentState);
        Assert.Equal(0.0, snapshot.Confidence);
    }

    [Fact]
    public void Update_RecentEvidence_OutweighsPartiallyDecayedOlderEvidence()
    {
        var estimator = new AttackStateEstimator(halfLife: TimeSpan.FromMinutes(10));
        var t0 = DateTimeOffset.UtcNow;

        estimator.Update("host-1", t0, new[] { Finding(AttackState.Discovery, AlertSeverity.Critical) });
        // One half-life later: old evidence is down to ~50%, but a strong new signal for a
        // different state should now dominate the distribution.
        var snapshot = estimator.Update("host-1", t0.AddMinutes(10), new[] { Finding(AttackState.CredentialAccess, AlertSeverity.Critical, 0.95) });

        Assert.Equal(AttackState.CredentialAccess, snapshot.CurrentState);
    }

    [Fact]
    public void PredictedNext_FollowsTransitionTable_ForDiscovery()
    {
        var estimator = new AttackStateEstimator();
        var snapshot = estimator.Update("host-1", DateTimeOffset.UtcNow, new[] { Finding(AttackState.Discovery, AlertSeverity.Critical) });

        Assert.NotEmpty(snapshot.PredictedNext);
        Assert.Contains(snapshot.PredictedNext, p => p.State == AttackState.LateralMovement);
    }

    [Fact]
    public void NextObjectivePredictor_RecommendsTelemetryIncrease_ForLateralMovement()
    {
        var advice = NextObjectivePredictor.RecommendedPreemptiveAction(AttackState.LateralMovement);
        Assert.Contains("SMB", advice);
    }
}
