namespace Aegis.Core.Patching;

/// <summary>
/// Drives a <see cref="PatchRolloutPlan"/> through doc §18's safe patch-orchestration
/// workflow. Every method is a guarded state transition: calling one from the wrong stage
/// throws rather than silently doing nothing or corrupting the plan, and every successful
/// transition is appended to <see cref="PatchRolloutPlan.History"/>. This is deliberately
/// pure orchestration/decision logic with no OS interaction - see
/// <c>Aegis.ResponseActions</c> for where an actual Windows Update Agent integration would
/// plug in to execute what this class decides (a seam, not yet implemented - see
/// docs/ARCHITECTURE.md).
/// </summary>
public sealed class PatchRolloutOrchestrator
{
    public PatchRolloutPlan ApplyTemporaryMitigation(PatchRolloutPlan plan, string reason)
    {
        RequireStage(plan, PatchRolloutStage.Assessed);
        plan.MitigationInPlace = true;
        return Transition(plan, PatchRolloutStage.MitigationApplied, reason);
    }

    public PatchRolloutPlan BeginCanaryTesting(PatchRolloutPlan plan, string reason)
    {
        RequireStage(plan, PatchRolloutStage.Assessed, PatchRolloutStage.MitigationApplied);
        return Transition(plan, PatchRolloutStage.CanaryTesting, reason);
    }

    /// <summary>doc §18 step 6. A failing canary health check rolls the whole plan back immediately - the update never reaches a single real ring host.</summary>
    public PatchRolloutPlan RecordCanaryHealthCheck(PatchRolloutPlan plan, HealthCheckResult result)
    {
        RequireStage(plan, PatchRolloutStage.CanaryTesting);

        if (!result.AllHealthy)
        {
            return Transition(plan, PatchRolloutStage.RolledBack, $"Canary health check failed: {DescribeFailure(result)}");
        }

        return Transition(plan, PatchRolloutStage.CanaryValidated, "Canary health check passed on all dimensions.");
    }

    public PatchRolloutPlan BeginRingDeployment(PatchRolloutPlan plan, string reason)
    {
        RequireStage(plan, PatchRolloutStage.CanaryValidated);
        if (plan.Rings.Count == 0) throw new InvalidOperationException("Plan has no deployment rings defined.");

        plan.CurrentRingIndex = 0;
        return Transition(plan, PatchRolloutStage.RingDeployment, reason);
    }

    /// <summary>
    /// doc §18 steps 8-9: observe telemetry/rollback criteria for the current ring, then
    /// either progress to the next ring, finish (all rings done -> Verified), or roll back
    /// the whole plan if this ring's health check failed. There is deliberately no "skip
    /// straight to the last ring" path - progressive rollout is the whole point.
    /// </summary>
    public PatchRolloutPlan RecordRingHealthCheck(PatchRolloutPlan plan, HealthCheckResult result)
    {
        RequireStage(plan, PatchRolloutStage.RingDeployment);
        if (plan.CurrentRingIndex < 0 || plan.CurrentRingIndex >= plan.Rings.Count)
            throw new InvalidOperationException("No active ring to record a health check against.");

        var ring = plan.Rings[plan.CurrentRingIndex];

        if (!result.AllHealthy)
        {
            return Transition(plan, PatchRolloutStage.RolledBack, $"Ring '{ring.Name}' health check failed: {DescribeFailure(result)}");
        }

        ring.Completed = true;
        var isLastRing = plan.CurrentRingIndex == plan.Rings.Count - 1;

        if (isLastRing)
        {
            return Transition(plan, PatchRolloutStage.Verified, $"Ring '{ring.Name}' (final ring) healthy - all rings complete.");
        }

        plan.CurrentRingIndex++;
        plan.History.Add(new PatchRolloutHistoryEntry(DateTimeOffset.UtcNow, plan.Stage, plan.Stage,
            $"Ring '{ring.Name}' healthy - advancing to ring '{plan.Rings[plan.CurrentRingIndex].Name}'."));
        return plan;
    }

    /// <summary>doc §18 step 10, second half: "close the temporary mitigation only after validation" - unreachable unless the plan actually reached Verified first.</summary>
    public PatchRolloutPlan CloseMitigationAfterVerification(PatchRolloutPlan plan, string reason)
    {
        RequireStage(plan, PatchRolloutStage.Verified);
        if (!plan.MitigationInPlace)
        {
            // No mitigation was ever applied (step 4 was skipped because exploitation risk
            // wasn't immediate) - this is a no-op transition straight to done, not an error.
            return Transition(plan, PatchRolloutStage.MitigationClosed, "No temporary mitigation was applied for this component - nothing to close.");
        }

        plan.MitigationInPlace = false;
        return Transition(plan, PatchRolloutStage.MitigationClosed, reason);
    }

    public PatchRolloutPlan Rollback(PatchRolloutPlan plan, string reason)
    {
        if (plan.Stage is PatchRolloutStage.Verified or PatchRolloutStage.MitigationClosed or PatchRolloutStage.RolledBack)
        {
            throw new InvalidOperationException($"Cannot roll back a plan already at '{plan.Stage}'.");
        }
        return Transition(plan, PatchRolloutStage.RolledBack, reason);
    }

    private static string DescribeFailure(HealthCheckResult result)
    {
        var failed = new List<string>();
        if (!result.ApplicationHealthy) failed.Add("application");
        if (!result.ServiceHealthy) failed.Add("service");
        if (!result.BootHealthy) failed.Add("boot");
        if (!result.AuthenticationHealthy) failed.Add("authentication");
        if (!result.NetworkHealthy) failed.Add("network");
        var notes = result.Notes.Count > 0 ? " (" + string.Join("; ", result.Notes) + ")" : "";
        return string.Join(", ", failed) + notes;
    }

    private static void RequireStage(PatchRolloutPlan plan, params PatchRolloutStage[] allowed)
    {
        if (!allowed.Contains(plan.Stage))
        {
            throw new InvalidOperationException(
                $"Cannot perform this action from stage '{plan.Stage}' - expected one of: {string.Join(", ", allowed)}.");
        }
    }

    private static PatchRolloutPlan Transition(PatchRolloutPlan plan, PatchRolloutStage to, string reason)
    {
        plan.History.Add(new PatchRolloutHistoryEntry(DateTimeOffset.UtcNow, plan.Stage, to, reason));
        plan.Stage = to;
        return plan;
    }
}
