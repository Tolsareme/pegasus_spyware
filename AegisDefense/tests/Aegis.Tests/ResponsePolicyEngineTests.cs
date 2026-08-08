using Aegis.Core.Events;
using Aegis.Core.Policy;
using Aegis.Core.Rules;
using Aegis.Core.Scoring;
using Xunit;

namespace Aegis.Tests;

public class ResponsePolicyEngineTests
{
    private static HostRiskBreakdown MakeRisk(double total, double autonomy, bool corroborated) => new()
    {
        HostId = "host-1",
        AsOf = DateTimeOffset.UtcNow,
        Total = total,
        Confidence = 0.8,
        AutonomyScore = autonomy,
        AutonomyComponents = new AutonomyScoreComponents(),
        ProcessBehavior = corroborated ? 0.6 : 0.0,
        IdentityRisk = corroborated ? 0.5 : 0.0,
        PersistenceRisk = corroborated ? 0.9 : 0.0,
        CredentialRisk = corroborated ? 0.8 : 0.0,
        LateralMovementRisk = corroborated ? 0.5 : 0.0,
        FileBehavior = corroborated ? 0.4 : 0.0,
        ContributingFindings = Array.Empty<RuleFinding>(),
    };

    [Fact]
    public void HighRisk_WithOnlyAutonomySignal_IsCappedAtRestrict()
    {
        var risk = MakeRisk(total: 90, autonomy: 0.9, corroborated: false);
        var engine = new ResponsePolicyEngine();
        var policy = DefensePolicy.CreateDefault();

        var decision = engine.Decide(risk, policy);

        Assert.Equal(ResponseLevel.Restrict, decision.Level);
        Assert.Contains(decision.Rationale, r => r.Contains("AutonomyScore is the dominant signal"));
    }

    [Fact]
    public void HighRisk_WithCorroboratingEvidence_ReachesContain()
    {
        var risk = MakeRisk(total: 90, autonomy: 0.9, corroborated: true);
        var engine = new ResponsePolicyEngine();
        var policy = DefensePolicy.CreateDefault();

        var decision = engine.Decide(risk, policy);

        Assert.Equal(ResponseLevel.EnterpriseResponse, decision.Level); // 90 >= default EnterpriseResponseAt(85)
    }

    [Fact]
    public void HighImpactAction_RequiresApproval_WhenNotInPlaybook()
    {
        var risk = MakeRisk(total: 75, autonomy: 0.3, corroborated: true); // -> Contain
        var engine = new ResponsePolicyEngine();
        var policy = DefensePolicy.CreateDefault();

        var decision = engine.Decide(risk, policy, candidatePlaybookActionId: "some-unlisted-action");

        Assert.True(decision.RequiresHumanApproval);
        Assert.False(decision.IsAutoExecutable);
    }

    [Fact]
    public void HighImpactAction_SkipsApproval_WhenPreauthorizedAndScoped()
    {
        var risk = MakeRisk(total: 75, autonomy: 0.3, corroborated: true);
        var engine = new ResponsePolicyEngine();
        var policy = DefensePolicy.CreateDefault();
        policy.Engines.AutoContainmentEnabled = true;

        var decision = engine.Decide(risk, policy, candidatePlaybookActionId: "isolate-test-endpoint");

        Assert.False(decision.RequiresHumanApproval);
        Assert.True(decision.IsAutoExecutable);
        Assert.Equal("isolate-test-endpoint", decision.MatchedPlaybookActionId);
    }

    [Fact]
    public void LowRisk_MapsToObserve_AndIsAlwaysAutoExecutable()
    {
        var risk = MakeRisk(total: 5, autonomy: 0.1, corroborated: false);
        var engine = new ResponsePolicyEngine();
        var policy = DefensePolicy.CreateDefault();

        var decision = engine.Decide(risk, policy);

        Assert.Equal(ResponseLevel.Observe, decision.Level);
        Assert.True(decision.IsAutoExecutable);
        Assert.False(decision.RequiresHumanApproval);
    }

    [Theory]
    [InlineData(20, ResponseLevel.Observe)]
    [InlineData(35, ResponseLevel.Enrich)]
    [InlineData(55, ResponseLevel.Restrict)]
    [InlineData(75, ResponseLevel.Contain)]
    [InlineData(90, ResponseLevel.EnterpriseResponse)]
    public void ResponseLevel_MatchesDefaultThresholdTable(double score, ResponseLevel expected)
    {
        var risk = MakeRisk(total: score, autonomy: 0.2, corroborated: true);
        var engine = new ResponsePolicyEngine();
        var decision = engine.Decide(risk, DefensePolicy.CreateDefault());

        Assert.Equal(expected, decision.Level);
    }
}
