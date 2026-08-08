using System.Text.Json.Serialization;

namespace Aegis.Core.Patching;

/// <summary>Mirrors doc §18's ten-step safe patch-orchestration workflow one-to-one, minus the two pure research/inventory steps (1-3) which happen before a plan exists.</summary>
public enum PatchRolloutStage
{
    /// <summary>Steps 1-3 done: component/version identified, vendor advisory mapped, exploitability assessed in this environment.</summary>
    Assessed,
    /// <summary>Step 4: a temporary mitigation (see VulnerabilityPrioritizer) is in place while the real fix is prepared.</summary>
    MitigationApplied,
    /// <summary>Step 5-6: vendor update is being tested against a canary/representative system.</summary>
    CanaryTesting,
    /// <summary>Step 6 passed: canary health checks (application/service/boot/auth/network) all green.</summary>
    CanaryValidated,
    /// <summary>Steps 7-9: progressively deploying to larger rings.</summary>
    RingDeployment,
    /// <summary>Step 10: update verified everywhere the plan targets.</summary>
    Verified,
    /// <summary>Step 10 completed: temporary mitigation from step 4 has been safely removed.</summary>
    MitigationClosed,
    /// <summary>A health check failed at some stage and the plan was rolled back - doc §26 "Automatic mitigation breaks applications" risk control.</summary>
    RolledBack,
}

/// <summary>One deployment ring - "canary group" through "everyone" (doc §18 step 7/9).</summary>
public sealed class RingDefinition
{
    public required string Name { get; init; }
    public required int TargetHostCount { get; init; }
    public bool Completed { get; set; }
}

/// <summary>doc §18 step 6: "Validate application, service, boot, authentication and network health."</summary>
public sealed record HealthCheckResult
{
    public required bool ApplicationHealthy { get; init; }
    public required bool ServiceHealthy { get; init; }
    public required bool BootHealthy { get; init; }
    public required bool AuthenticationHealthy { get; init; }
    public required bool NetworkHealthy { get; init; }
    public IReadOnlyList<string> Notes { get; init; } = Array.Empty<string>();

    public bool AllHealthy => ApplicationHealthy && ServiceHealthy && BootHealthy && AuthenticationHealthy && NetworkHealthy;

    public static HealthCheckResult Healthy() => new()
    {
        ApplicationHealthy = true, ServiceHealthy = true, BootHealthy = true, AuthenticationHealthy = true, NetworkHealthy = true,
    };
}

/// <summary>A single stage transition, kept for the plan's audit trail (doc §29 "log every automated decision").</summary>
public sealed record PatchRolloutHistoryEntry(DateTimeOffset At, PatchRolloutStage From, PatchRolloutStage To, string Reason);

/// <summary>
/// The state a <see cref="PatchRolloutOrchestrator"/> operates on. Mutated only through the
/// orchestrator's methods, never directly, so every transition goes through the same guard
/// conditions and gets recorded in <see cref="History"/>.
/// </summary>
public sealed class PatchRolloutPlan
{
    public Guid PlanId { get; init; } = Guid.NewGuid();
    public required string Component { get; init; }
    public required string VendorAdvisoryReference { get; init; }
    public required IReadOnlyList<RingDefinition> Rings { get; init; }

    // JsonInclude: the setters are internal (only the orchestrator should mutate a plan) but
    // Aegis.Data (a different assembly) still needs to round-trip these fields through JSON
    // for persistence - JsonInclude lets System.Text.Json use the internal setter via
    // reflection without widening it to public for ordinary C# callers.
    [JsonInclude]
    public PatchRolloutStage Stage { get; internal set; } = PatchRolloutStage.Assessed;
    [JsonInclude]
    public int CurrentRingIndex { get; internal set; } = -1;
    [JsonInclude]
    public bool MitigationInPlace { get; internal set; }
    // A plain get-only collection property does not reliably round-trip through
    // System.Text.Json when the containing type also has `required` members (observed
    // empirically - the "populate existing collection instance" fallback does not kick in on
    // that code path), so this needs an actual (internal) setter + JsonInclude like the other
    // orchestrator-only-mutable fields above, even though normal orchestrator code only ever
    // calls .Add() through the getter and never assigns a new list itself.
    [JsonInclude]
    public List<PatchRolloutHistoryEntry> History { get; internal set; } = new();
}
