using Aegis.Core.Patching;
using Xunit;

namespace Aegis.Tests;

public class PatchRolloutOrchestratorTests
{
    private static PatchRolloutPlan MakePlan(int ringCount = 3) => new()
    {
        Component = "Widgets.Service 4.2",
        VendorAdvisoryReference = "CVE-2026-00001",
        Rings = Enumerable.Range(1, ringCount).Select(i => new RingDefinition { Name = $"Ring {i}", TargetHostCount = i * 10 }).ToList(),
    };

    [Fact]
    public void HappyPath_GoesFromAssessedToMitigationClosed()
    {
        var orchestrator = new PatchRolloutOrchestrator();
        var plan = MakePlan();

        orchestrator.ApplyTemporaryMitigation(plan, "Internet-facing, actively exploited.");
        Assert.Equal(PatchRolloutStage.MitigationApplied, plan.Stage);
        Assert.True(plan.MitigationInPlace);

        orchestrator.BeginCanaryTesting(plan, "Vendor patch available.");
        Assert.Equal(PatchRolloutStage.CanaryTesting, plan.Stage);

        orchestrator.RecordCanaryHealthCheck(plan, HealthCheckResult.Healthy());
        Assert.Equal(PatchRolloutStage.CanaryValidated, plan.Stage);

        orchestrator.BeginRingDeployment(plan, "Canary validated.");
        Assert.Equal(PatchRolloutStage.RingDeployment, plan.Stage);
        Assert.Equal(0, plan.CurrentRingIndex);

        orchestrator.RecordRingHealthCheck(plan, HealthCheckResult.Healthy());
        Assert.Equal(PatchRolloutStage.RingDeployment, plan.Stage); // still deploying - ring 2 next
        Assert.Equal(1, plan.CurrentRingIndex);

        orchestrator.RecordRingHealthCheck(plan, HealthCheckResult.Healthy());
        Assert.Equal(2, plan.CurrentRingIndex);

        orchestrator.RecordRingHealthCheck(plan, HealthCheckResult.Healthy()); // final ring
        Assert.Equal(PatchRolloutStage.Verified, plan.Stage);
        Assert.True(plan.Rings.All(r => r.Completed));

        orchestrator.CloseMitigationAfterVerification(plan, "Update verified everywhere; mitigation no longer needed.");
        Assert.Equal(PatchRolloutStage.MitigationClosed, plan.Stage);
        Assert.False(plan.MitigationInPlace);
    }

    [Fact]
    public void SkippingMitigation_StillReachesMitigationClosed_AsNoOp()
    {
        var orchestrator = new PatchRolloutOrchestrator();
        var plan = MakePlan(ringCount: 1);

        // No ApplyTemporaryMitigation call - exploitation risk wasn't immediate.
        orchestrator.BeginCanaryTesting(plan, "Routine patch cycle.");
        orchestrator.RecordCanaryHealthCheck(plan, HealthCheckResult.Healthy());
        orchestrator.BeginRingDeployment(plan, "Go.");
        orchestrator.RecordRingHealthCheck(plan, HealthCheckResult.Healthy());

        Assert.Equal(PatchRolloutStage.Verified, plan.Stage);
        Assert.False(plan.MitigationInPlace);

        orchestrator.CloseMitigationAfterVerification(plan, "n/a");
        Assert.Equal(PatchRolloutStage.MitigationClosed, plan.Stage);
    }

    [Fact]
    public void FailedCanaryHealthCheck_RollsBack_BeforeTouchingAnyRing()
    {
        var orchestrator = new PatchRolloutOrchestrator();
        var plan = MakePlan();
        orchestrator.BeginCanaryTesting(plan, "Testing.");

        var badHealth = new HealthCheckResult
        {
            ApplicationHealthy = false, ServiceHealthy = true, BootHealthy = true, AuthenticationHealthy = true, NetworkHealthy = true,
            Notes = new[] { "App crashes on startup after update." },
        };
        orchestrator.RecordCanaryHealthCheck(plan, badHealth);

        Assert.Equal(PatchRolloutStage.RolledBack, plan.Stage);
        Assert.Contains(plan.History, h => h.Reason.Contains("application") && h.Reason.Contains("crashes"));
    }

    [Fact]
    public void FailedRingHealthCheck_RollsBackWholePlan_NotJustThatRing()
    {
        var orchestrator = new PatchRolloutOrchestrator();
        var plan = MakePlan();
        orchestrator.BeginCanaryTesting(plan, "Testing.");
        orchestrator.RecordCanaryHealthCheck(plan, HealthCheckResult.Healthy());
        orchestrator.BeginRingDeployment(plan, "Go.");
        orchestrator.RecordRingHealthCheck(plan, HealthCheckResult.Healthy()); // ring 1 ok

        var badHealth = new HealthCheckResult
        {
            ApplicationHealthy = true, ServiceHealthy = true, BootHealthy = true, AuthenticationHealthy = false, NetworkHealthy = true,
        };
        orchestrator.RecordRingHealthCheck(plan, badHealth); // ring 2 fails

        Assert.Equal(PatchRolloutStage.RolledBack, plan.Stage);
        Assert.True(plan.Rings[0].Completed);
        Assert.False(plan.Rings[1].Completed);
        Assert.False(plan.Rings[2].Completed);
    }

    [Fact]
    public void CannotSkipCanaryTesting_DirectlyToRingDeployment()
    {
        var orchestrator = new PatchRolloutOrchestrator();
        var plan = MakePlan();

        var ex = Assert.Throws<InvalidOperationException>(() => orchestrator.BeginRingDeployment(plan, "shortcut"));
        Assert.Contains("Assessed", ex.Message);
    }

    [Fact]
    public void CannotRecordRingHealthCheck_BeforeRingDeploymentStarted()
    {
        var orchestrator = new PatchRolloutOrchestrator();
        var plan = MakePlan();
        orchestrator.BeginCanaryTesting(plan, "x");
        orchestrator.RecordCanaryHealthCheck(plan, HealthCheckResult.Healthy());

        Assert.Throws<InvalidOperationException>(() => orchestrator.RecordRingHealthCheck(plan, HealthCheckResult.Healthy()));
    }

    [Fact]
    public void CannotCloseMitigation_BeforeVerified()
    {
        var orchestrator = new PatchRolloutOrchestrator();
        var plan = MakePlan();
        orchestrator.ApplyTemporaryMitigation(plan, "x");

        Assert.Throws<InvalidOperationException>(() => orchestrator.CloseMitigationAfterVerification(plan, "too early"));
    }

    [Fact]
    public void CannotRollBack_AnAlreadyCompletedPlan()
    {
        var orchestrator = new PatchRolloutOrchestrator();
        var plan = MakePlan(ringCount: 1);
        orchestrator.BeginCanaryTesting(plan, "x");
        orchestrator.RecordCanaryHealthCheck(plan, HealthCheckResult.Healthy());
        orchestrator.BeginRingDeployment(plan, "x");
        orchestrator.RecordRingHealthCheck(plan, HealthCheckResult.Healthy());
        orchestrator.CloseMitigationAfterVerification(plan, "x");

        Assert.Throws<InvalidOperationException>(() => orchestrator.Rollback(plan, "too late"));
    }

    [Fact]
    public void ManualRollback_IsAllowed_FromAnyInProgressStage()
    {
        var orchestrator = new PatchRolloutOrchestrator();
        var plan = MakePlan();
        orchestrator.ApplyTemporaryMitigation(plan, "x");

        orchestrator.Rollback(plan, "Operator aborted - vendor pulled the update.");

        Assert.Equal(PatchRolloutStage.RolledBack, plan.Stage);
    }

    [Fact]
    public void EveryTransition_IsRecordedInHistory()
    {
        var orchestrator = new PatchRolloutOrchestrator();
        var plan = MakePlan(ringCount: 1);

        orchestrator.BeginCanaryTesting(plan, "start");
        orchestrator.RecordCanaryHealthCheck(plan, HealthCheckResult.Healthy());
        orchestrator.BeginRingDeployment(plan, "go");
        orchestrator.RecordRingHealthCheck(plan, HealthCheckResult.Healthy());

        Assert.True(plan.History.Count >= 4);
        Assert.All(plan.History, h => Assert.False(string.IsNullOrWhiteSpace(h.Reason)));
    }
}
