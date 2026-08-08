using Aegis.Core.Events;
using Aegis.Core.Features;
using Aegis.Core.Rules;
using Aegis.Core.Scoring;
using Xunit;

namespace Aegis.Tests;

public class ScoringTests
{
    private static FeatureSnapshot Quiet() => new() { HostId = "h1", AsOf = DateTimeOffset.UtcNow };

    [Fact]
    public void AutonomyScore_IsZero_ForQuietHost()
    {
        var result = AutonomyScoreCalculator.Compute(Quiet());
        Assert.Equal(0.0, result.Score, precision: 6);
    }

    [Fact]
    public void AutonomyScore_IsBounded_EvenWithExtremeInputs()
    {
        var extreme = Quiet() with
        {
            WindowEventCount = 100_000,
            TechniqueSwitchAfterFailureCount = 999,
            AuthFailureThenSuccessCount = 999,
            NewDestinationCount = 999,
            RemoteContactRate = 999,
            CrossHostSimilarHostCount = 999,
            ReconToActionSeconds = 0,
        };

        var result = AutonomyScoreCalculator.Compute(extreme);

        Assert.InRange(result.Score, 0.0, 1.0);
        Assert.True(result.Score > 0.9, $"Expected near-max autonomy score, got {result.Score}");
    }

    [Fact]
    public void AutonomyScore_RewardsFastResultToNextActionLatency()
    {
        var fast = Quiet() with { ReconToActionSeconds = 5 };
        var slow = Quiet() with { ReconToActionSeconds = 290 };

        var fastScore = AutonomyScoreCalculator.Compute(fast).Score;
        var slowScore = AutonomyScoreCalculator.Compute(slow).Score;

        Assert.True(fastScore > slowScore);
    }

    [Fact]
    public void HostRisk_ZeroForQuietHost_WithNoFindings()
    {
        var risk = HostRiskCalculator.Compute(Quiet(), Array.Empty<RuleFinding>());
        Assert.Equal(0.0, risk.Total, precision: 3);
    }

    [Fact]
    public void HostRisk_Total_Increases_WithPersistenceAndCredentialSignals()
    {
        var quiet = HostRiskCalculator.Compute(Quiet(), Array.Empty<RuleFinding>());
        var loaded = Quiet() with
        {
            PersistenceAfterExecutionSeconds = 60,
            CredentialToRemoteAuthSeconds = 120,
            NewDestinationCount = 8,
        };
        var loadedRisk = HostRiskCalculator.Compute(loaded, Array.Empty<RuleFinding>());

        Assert.True(loadedRisk.Total > quiet.Total);
    }

    [Fact]
    public void HostRisk_Confidence_IsLower_ForSparseEvidence()
    {
        var sparse = HostRiskCalculator.Compute(Quiet() with { WindowEventCount = 1 }, Array.Empty<RuleFinding>());
        var dense = HostRiskCalculator.Compute(Quiet() with { WindowEventCount = 200 },
            new[] { MakeFinding(), MakeFinding(), MakeFinding() });

        Assert.True(dense.Confidence > sparse.Confidence);
    }

    private static RuleFinding MakeFinding() => new()
    {
        RuleId = "TEST",
        Name = "test",
        Description = "test",
        Severity = AlertSeverity.Medium,
        StateHint = AttackState.Discovery,
        Confidence = 0.6,
        TriggeringEventId = Guid.NewGuid(),
    };
}
