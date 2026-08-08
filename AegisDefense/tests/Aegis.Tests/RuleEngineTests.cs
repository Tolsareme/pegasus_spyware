using Aegis.Core.Events;
using Aegis.Core.Features;
using Aegis.Core.Rules;
using Xunit;

namespace Aegis.Tests;

public class RuleEngineTests
{
    private static NormalizedEvent MakeEvent(ActionType type = ActionType.ProcessCreate, ObjectType objectType = ObjectType.Unknown, string? objectId = null, string? signer = null, string? hostRole = "Workstation") => new()
    {
        EventId = Guid.NewGuid(),
        Timestamp = DateTimeOffset.UtcNow,
        HostId = "host-1",
        ActionType = type,
        ObjectType = objectType,
        ObjectId = objectId,
        Signer = signer,
        HostRole = hostRole,
    };

    private static FeatureSnapshot BaseFeatures(string hostId = "host-1") => new()
    {
        HostId = hostId,
        AsOf = DateTimeOffset.UtcNow,
    };

    [Fact]
    public void CanaryResourceAccessRule_Fires_OnDecoyObjectType()
    {
        var evt = MakeEvent(ActionType.CanaryAccess, ObjectType.DecoyResource, "decoy-1");
        var engine = new RuleEngine();

        var findings = engine.Evaluate(new RuleContext(evt, BaseFeatures()));

        Assert.Contains(findings, f => f.RuleId == "AEG-014");
        var finding = findings.Single(f => f.RuleId == "AEG-014");
        Assert.Equal(AlertSeverity.Critical, finding.Severity);
        Assert.True(finding.Confidence > 0.9);
    }

    [Fact]
    public void UnsignedDriverLoadRule_DoesNotFire_WhenSignerPresent()
    {
        var evt = MakeEvent(ActionType.DriverLoad, signer: "Microsoft Windows");
        var engine = new RuleEngine();

        var findings = engine.Evaluate(new RuleContext(evt, BaseFeatures()));

        Assert.DoesNotContain(findings, f => f.RuleId == "AEG-013");
    }

    [Fact]
    public void UnsignedDriverLoadRule_Fires_WhenSignerMissing()
    {
        var evt = MakeEvent(ActionType.DriverLoad, signer: null);
        var engine = new RuleEngine();

        var findings = engine.Evaluate(new RuleContext(evt, BaseFeatures()));

        Assert.Contains(findings, f => f.RuleId == "AEG-013" && f.Severity == AlertSeverity.Critical);
    }

    [Fact]
    public void RapidTechniqueSwitchRule_RequiresAtLeastTwoSwitches()
    {
        var evt = MakeEvent();
        var oneSwitch = BaseFeatures() with { TechniqueSwitchAfterFailureCount = 1 };
        var twoSwitches = BaseFeatures() with { TechniqueSwitchAfterFailureCount = 2 };
        var engine = new RuleEngine();

        Assert.DoesNotContain(engine.Evaluate(new RuleContext(evt, oneSwitch)), f => f.RuleId == "AEG-002");
        Assert.Contains(engine.Evaluate(new RuleContext(evt, twoSwitches)), f => f.RuleId == "AEG-002");
    }

    [Fact]
    public void MassFileModificationRule_EscalatesToCritical_WhenHighEntropy()
    {
        var evt = MakeEvent(ActionType.FileWrite);
        var burstNoEntropy = BaseFeatures() with { FileWriteBurstCount = 30, HighEntropyWriteObserved = false };
        var burstWithEntropy = BaseFeatures() with { FileWriteBurstCount = 30, HighEntropyWriteObserved = true };
        var engine = new RuleEngine();

        var noEntropyFinding = engine.Evaluate(new RuleContext(evt, burstNoEntropy)).Single(f => f.RuleId == "AEG-015");
        var entropyFinding = engine.Evaluate(new RuleContext(evt, burstWithEntropy)).Single(f => f.RuleId == "AEG-015");

        Assert.Equal(AlertSeverity.High, noEntropyFinding.Severity);
        Assert.Equal(AlertSeverity.Critical, entropyFinding.Severity);
    }

    [Fact]
    public void RuleEngine_IsolatesExceptions_FromOneMisbehavingRule()
    {
        var throwing = new ThrowingRule();
        var engine = new RuleEngine(new IDetectionRule[] { throwing, new CanaryResourceAccessRuleProxy() });
        var evt = MakeEvent(ActionType.CanaryAccess, ObjectType.DecoyResource, "decoy-1");

        var findings = engine.Evaluate(new RuleContext(evt, BaseFeatures()));

        Assert.Single(findings);
    }

    private sealed class ThrowingRule : IDetectionRule
    {
        public string Id => "TEST-THROW";
        public string Name => "Throws";
        public RuleFinding? Evaluate(RuleContext context) => throw new InvalidOperationException("boom");
    }

    /// <summary>Wraps a built-in rule via reflection-free re-implementation so the exception-isolation test doesn't depend on internal visibility.</summary>
    private sealed class CanaryResourceAccessRuleProxy : IDetectionRule
    {
        public string Id => "AEG-014";
        public string Name => "Canary/decoy resource accessed";
        public RuleFinding? Evaluate(RuleContext ctx)
        {
            if (ctx.Event.ActionType != ActionType.CanaryAccess && ctx.Event.ObjectType != ObjectType.DecoyResource) return null;
            return new RuleFinding { RuleId = Id, Name = Name, Description = "hit", Severity = AlertSeverity.Critical, StateHint = AttackState.Discovery, Confidence = 0.97, TriggeringEventId = ctx.Event.EventId };
        }
    }
}
