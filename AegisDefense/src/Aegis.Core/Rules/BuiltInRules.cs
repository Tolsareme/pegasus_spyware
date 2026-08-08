using Aegis.Core.Events;

namespace Aegis.Core.Rules;

/// <summary>
/// The MVP's "ten to twenty high-confidence behavioral correlation rules" (doc §24).
/// Each rule is intentionally narrow and named after the specific behavior it targets so
/// findings read naturally in the GUI's evidence trail. Thresholds are simple constants
/// here; production deployments are expected to move them into the signed policy file
/// (see <see cref="Aegis.Core.Policy.DefensePolicy"/>) so they can be tuned without a
/// rebuild - the interface makes that swap trivial.
/// </summary>
public static class BuiltInRules
{
    public static IReadOnlyList<IDetectionRule> All { get; } = new IDetectionRule[]
    {
        new HighActionFrequencyRule(),
        new RapidTechniqueSwitchRule(),
        new SystematicEnumerationRule(),
        new AuthFailureThenSuccessRule(),
        new UnusualLogonTypeRule(),
        new RareProcessLineageRule(),
        new ObfuscatedScriptExecutionRule(),
        new PersistenceAfterSuspiciousExecutionRule(),
        new CredentialAccessThenRemoteAuthRule(),
        new ReconToActionPivotRule(),
        new PrivilegeChangeBurstRule(),
        new ServerPersistenceArtifactRule(),
        new UnsignedDriverLoadRule(),
        new CanaryResourceAccessRule(),
        new MassFileModificationRule(),
        new SecurityControlTamperingRule(),
    };
}

internal sealed class HighActionFrequencyRule : IDetectionRule
{
    public string Id => "AEG-001";
    public string Name => "High action frequency";

    public RuleFinding? Evaluate(RuleContext ctx)
    {
        if (ctx.Features.WindowEventCount < 150) return null; // >~5/min sustained over a 30 min window
        return new RuleFinding
        {
            RuleId = Id,
            Name = Name,
            Description = $"Host {ctx.Event.HostId} produced {ctx.Features.WindowEventCount} observable actions in the current window - well above manual-administration pace.",
            Severity = AlertSeverity.Medium,
            StateHint = AttackState.Discovery,
            Confidence = 0.55,
            TriggeringEventId = ctx.Event.EventId,
        };
    }
}

internal sealed class RapidTechniqueSwitchRule : IDetectionRule
{
    public string Id => "AEG-002";
    public string Name => "Rapid technique switching after failure";

    public RuleFinding? Evaluate(RuleContext ctx)
    {
        if (ctx.Features.TechniqueSwitchAfterFailureCount < 2) return null;
        return new RuleFinding
        {
            RuleId = Id,
            Name = Name,
            Description = $"{ctx.Features.TechniqueSwitchAfterFailureCount} instances of an alternate technique immediately following a failed action - a hallmark of machine-speed adaptation (doc §3.1/§11).",
            Severity = AlertSeverity.High,
            StateHint = AttackState.DefenseEvasion,
            Confidence = 0.75,
            TriggeringEventId = ctx.Event.EventId,
        };
    }
}

internal sealed class SystematicEnumerationRule : IDetectionRule
{
    public string Id => "AEG-003";
    public string Name => "Systematic enumeration across hosts";

    public RuleFinding? Evaluate(RuleContext ctx)
    {
        if (ctx.Features.RemoteContactRate < 1.0 || ctx.Features.NewDestinationCount < 5) return null;
        return new RuleFinding
        {
            RuleId = Id,
            Name = Name,
            Description = $"{ctx.Features.NewDestinationCount} previously-uncontacted hosts reached at {ctx.Features.RemoteContactRate:F1}/min - consistent with systematic network enumeration.",
            Severity = AlertSeverity.Medium,
            StateHint = AttackState.Discovery,
            Confidence = 0.6,
            TriggeringEventId = ctx.Event.EventId,
        };
    }
}

internal sealed class AuthFailureThenSuccessRule : IDetectionRule
{
    public string Id => "AEG-004";
    public string Name => "Authentication failure immediately followed by success";

    public RuleFinding? Evaluate(RuleContext ctx)
    {
        if (ctx.Features.AuthFailureThenSuccessCount < 1) return null;
        var severity = ctx.Features.AuthFailureCount >= 5 ? AlertSeverity.High : AlertSeverity.Medium;
        return new RuleFinding
        {
            RuleId = Id,
            Name = Name,
            Description = $"{ctx.Features.AuthFailureThenSuccessCount} failure-then-success authentication transitions ({ctx.Features.AuthFailureCount} total failures in window) - possible credential guessing or spraying.",
            Severity = severity,
            StateHint = AttackState.CredentialAccess,
            Confidence = 0.65,
            TriggeringEventId = ctx.Event.EventId,
        };
    }
}

internal sealed class UnusualLogonTypeRule : IDetectionRule
{
    public string Id => "AEG-005";
    public string Name => "Unusual logon type for identity";

    public RuleFinding? Evaluate(RuleContext ctx)
    {
        if (ctx.Features.UnusualLogonTypeCount < 1) return null;
        return new RuleFinding
        {
            RuleId = Id,
            Name = Name,
            Description = "Identity authenticated using a logon type it has not previously used on this host.",
            Severity = AlertSeverity.Low,
            StateHint = AttackState.InitialAccess,
            Confidence = 0.4,
            TriggeringEventId = ctx.Event.EventId,
        };
    }
}

internal sealed class RareProcessLineageRule : IDetectionRule
{
    public string Id => "AEG-006";
    public string Name => "Rare process lineage";

    public RuleFinding? Evaluate(RuleContext ctx)
    {
        if (ctx.Event.ActionType != ActionType.ProcessCreate) return null;
        if (ctx.Features.ProcessRarity < 0.85) return null;
        return new RuleFinding
        {
            RuleId = Id,
            Name = Name,
            Description = $"Process '{ctx.Event.ImagePath}' spawned by '{ctx.Event.ParentImagePath ?? "?"}' is a lineage never (or almost never) seen for this host role (rarity={ctx.Features.ProcessRarity:F2}).",
            Severity = AlertSeverity.Medium,
            StateHint = AttackState.Execution,
            Confidence = 0.5,
            TriggeringEventId = ctx.Event.EventId,
        };
    }
}

internal sealed class ObfuscatedScriptExecutionRule : IDetectionRule
{
    public string Id => "AEG-007";
    public string Name => "Obfuscated script/command execution";

    public RuleFinding? Evaluate(RuleContext ctx)
    {
        if (ctx.Event.ActionType is not (ActionType.ProcessCreate or ActionType.ScriptExecution)) return null;
        if (ctx.Features.CommandComplexity < 0.4) return null;
        return new RuleFinding
        {
            RuleId = Id,
            Name = Name,
            Description = $"Command/script shows obfuscation indicators (score={ctx.Features.CommandComplexity:F2}): {Truncate(ctx.Event.CommandLine)}",
            Severity = AlertSeverity.Medium,
            StateHint = AttackState.DefenseEvasion,
            Confidence = 0.6,
            TriggeringEventId = ctx.Event.EventId,
        };
    }

    private static string Truncate(string? s) => s is null || s.Length == 0 ? string.Empty : (s.Length <= 120 ? s : s.Substring(0, 120) + "...");
}

internal sealed class PersistenceAfterSuspiciousExecutionRule : IDetectionRule
{
    public string Id => "AEG-008";
    public string Name => "Persistence created shortly after suspicious execution";

    public RuleFinding? Evaluate(RuleContext ctx)
    {
        if (ctx.Features.PersistenceAfterExecutionSeconds is not { } seconds) return null;
        return new RuleFinding
        {
            RuleId = Id,
            Name = Name,
            Description = $"Persistence artifact created {seconds:F0}s after a suspicious execution on the same host.",
            Severity = AlertSeverity.High,
            StateHint = AttackState.Persistence,
            Confidence = 0.7,
            TriggeringEventId = ctx.Event.EventId,
        };
    }
}

internal sealed class CredentialAccessThenRemoteAuthRule : IDetectionRule
{
    public string Id => "AEG-009";
    public string Name => "Credential access followed by remote authentication";

    public RuleFinding? Evaluate(RuleContext ctx)
    {
        if (ctx.Features.CredentialToRemoteAuthSeconds is not { } seconds) return null;
        return new RuleFinding
        {
            RuleId = Id,
            Name = Name,
            Description = $"Remote authentication occurred {seconds:F0}s after credential-sensitive access on this host - possible lateral movement using harvested credentials.",
            Severity = AlertSeverity.High,
            StateHint = AttackState.LateralMovement,
            Confidence = 0.7,
            TriggeringEventId = ctx.Event.EventId,
        };
    }
}

internal sealed class ReconToActionPivotRule : IDetectionRule
{
    public string Id => "AEG-010";
    public string Name => "Immediate pivot from reconnaissance to action";

    public RuleFinding? Evaluate(RuleContext ctx)
    {
        if (ctx.Features.ReconToActionSeconds is not { } seconds || seconds > 60) return null;
        return new RuleFinding
        {
            RuleId = Id,
            Name = Name,
            Description = $"Action taken only {seconds:F0}s after a discovery/reconnaissance result - faster than typical manual triage of recon output.",
            Severity = AlertSeverity.Medium,
            StateHint = AttackState.Discovery,
            Confidence = 0.55,
            TriggeringEventId = ctx.Event.EventId,
        };
    }
}

internal sealed class PrivilegeChangeBurstRule : IDetectionRule
{
    public string Id => "AEG-011";
    public string Name => "Burst of privilege/security-control changes";

    public RuleFinding? Evaluate(RuleContext ctx)
    {
        if (ctx.Features.PrivilegeChangeCount < 3) return null;
        return new RuleFinding
        {
            RuleId = Id,
            Name = Name,
            Description = $"{ctx.Features.PrivilegeChangeCount} privilege or security-control changes observed in the current window.",
            Severity = AlertSeverity.High,
            StateHint = AttackState.PrivilegeEscalation,
            Confidence = 0.65,
            TriggeringEventId = ctx.Event.EventId,
        };
    }
}

internal sealed class ServerPersistenceArtifactRule : IDetectionRule
{
    public string Id => "AEG-012";
    public string Name => "New persistence artifact on a server role";

    public RuleFinding? Evaluate(RuleContext ctx)
    {
        var isPersistence = ctx.Event.ActionType is ActionType.ServiceCreate or ActionType.ScheduledTaskCreate;
        var isServer = ctx.Event.HostRole is not null &&
                       ctx.Event.HostRole.IndexOf("Server", StringComparison.OrdinalIgnoreCase) >= 0;
        if (!isPersistence || !isServer) return null;
        return new RuleFinding
        {
            RuleId = Id,
            Name = Name,
            Description = $"New {ctx.Event.ActionType} on server host {ctx.Event.HostId} - persistence on server roles carries higher business impact.",
            Severity = AlertSeverity.High,
            StateHint = AttackState.Persistence,
            Confidence = 0.5,
            TriggeringEventId = ctx.Event.EventId,
        };
    }
}

internal sealed class UnsignedDriverLoadRule : IDetectionRule
{
    public string Id => "AEG-013";
    public string Name => "Unsigned or unknown driver load";

    public RuleFinding? Evaluate(RuleContext ctx)
    {
        if (ctx.Event.ActionType != ActionType.DriverLoad) return null;
        if (!string.IsNullOrEmpty(ctx.Event.Signer)) return null;
        return new RuleFinding
        {
            RuleId = Id,
            Name = Name,
            Description = $"Driver '{ctx.Event.ImagePath}' loaded without a recognized signer - kernel-level risk (doc §5 Drivers).",
            Severity = AlertSeverity.Critical,
            StateHint = AttackState.DefenseEvasion,
            Confidence = 0.8,
            TriggeringEventId = ctx.Event.EventId,
        };
    }
}

internal sealed class CanaryResourceAccessRule : IDetectionRule
{
    public string Id => "AEG-014";
    public string Name => "Canary/decoy resource accessed";

    public RuleFinding? Evaluate(RuleContext ctx)
    {
        if (ctx.Event.ActionType != ActionType.CanaryAccess && ctx.Event.ObjectType != ObjectType.DecoyResource) return null;
        return new RuleFinding
        {
            RuleId = Id,
            Name = Name,
            Description = "A decoy resource was accessed. Legitimate users/software have no reason to touch it (doc §15) - very high confidence of malicious reconnaissance or compromise.",
            Severity = AlertSeverity.Critical,
            StateHint = AttackState.Discovery,
            Confidence = 0.97,
            TriggeringEventId = ctx.Event.EventId,
        };
    }
}

internal sealed class MassFileModificationRule : IDetectionRule
{
    public string Id => "AEG-015";
    public string Name => "Mass file modification / possible destructive payload";

    public RuleFinding? Evaluate(RuleContext ctx)
    {
        if (ctx.Features.FileWriteBurstCount < 25) return null;
        var severity = ctx.Features.HighEntropyWriteObserved ? AlertSeverity.Critical : AlertSeverity.High;
        return new RuleFinding
        {
            RuleId = Id,
            Name = Name,
            Description = $"{ctx.Features.FileWriteBurstCount} file creations/writes/deletes in the last 60s" +
                          (ctx.Features.HighEntropyWriteObserved ? " with high-entropy (encrypted-looking) content - consistent with ransomware." : "."),
            Severity = severity,
            StateHint = AttackState.Collection,
            Confidence = ctx.Features.HighEntropyWriteObserved ? 0.85 : 0.6,
            TriggeringEventId = ctx.Event.EventId,
        };
    }
}

internal sealed class SecurityControlTamperingRule : IDetectionRule
{
    public string Id => "AEG-016";
    public string Name => "Security control tampering";

    public RuleFinding? Evaluate(RuleContext ctx)
    {
        if (ctx.Event.ActionType != ActionType.SecurityControlChange) return null;
        return new RuleFinding
        {
            RuleId = Id,
            Name = Name,
            Description = $"Security-control configuration changed on {ctx.Event.HostId} (object: {ctx.Event.ObjectId ?? "unknown"}).",
            Severity = AlertSeverity.High,
            StateHint = AttackState.DefenseEvasion,
            Confidence = 0.7,
            TriggeringEventId = ctx.Event.EventId,
        };
    }
}
