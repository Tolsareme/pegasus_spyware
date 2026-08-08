using Aegis.Core.Events;
using Aegis.Core.Scoring;

namespace Aegis.Core.Policy;

/// <summary>Result of evaluating one HostRisk snapshot against the active policy - what the response engine is allowed to do, and why.</summary>
public sealed record ResponseDecision
{
    public required string HostId { get; init; }
    public required ResponseLevel Level { get; init; }
    public required bool RequiresHumanApproval { get; init; }
    public required bool IsAutoExecutable { get; init; }
    public required IReadOnlyList<string> Rationale { get; init; }
    public string? MatchedPlaybookActionId { get; init; }
}

/// <summary>
/// Turns a HostRiskBreakdown into a graduated, policy-bounded decision (doc §14). Two
/// safety rules are enforced unconditionally, regardless of policy contents, because they
/// are load-bearing safety properties rather than tunable behavior:
///   1. AutonomyScore alone can never justify Contain/EnterpriseResponse (doc §11: "should
///      never be the sole reason for destructive remediation").
///   2. Contain/EnterpriseResponse only auto-execute when AutoContainmentEnabled is on AND
///      either the action is not "high impact" or it is explicitly pre-authorized in the
///      signed policy's emergency playbook (doc §14/§29).
/// </summary>
public sealed class ResponsePolicyEngine
{
    public ResponseDecision Decide(HostRiskBreakdown risk, DefensePolicy policy, string? candidatePlaybookActionId = null)
    {
        var rationale = new List<string>();
        var level = LevelForScore(risk.Total, policy.Thresholds);
        rationale.Add($"Composite risk {risk.Total:F1}/100 maps to {level} under current thresholds.");

        // Safety rule 1: AutonomyScore cannot be the sole driver of a high-impact response.
        if (level is ResponseLevel.Contain or ResponseLevel.EnterpriseResponse && IsAutonomyDominated(risk))
        {
            level = ResponseLevel.Restrict;
            rationale.Add("Capped at Restrict: AutonomyScore is the dominant signal and per policy cannot alone justify Contain/EnterpriseResponse - corroborating evidence (identity, credential, lateral-movement, or file-behavior risk) is required first.");
        }

        var isHighImpact = level is ResponseLevel.Contain or ResponseLevel.EnterpriseResponse;
        var requiresApproval = isHighImpact && policy.HighImpactActionsRequireApproval;
        var matchedEntry = candidatePlaybookActionId is null
            ? null
            : policy.EmergencyPlaybook.FirstOrDefault(e =>
                e.ActionId == candidatePlaybookActionId &&
                (e.HostIdScope is null || string.Equals(e.HostIdScope, risk.HostId, StringComparison.OrdinalIgnoreCase)));

        if (isHighImpact && matchedEntry is not null)
        {
            requiresApproval = false;
            rationale.Add($"Action '{matchedEntry.ActionId}' is pre-authorized in the signed emergency playbook and scoped to this host - proceeding without live approval.");
        }
        else if (isHighImpact && requiresApproval)
        {
            rationale.Add("High-impact action requires explicit human/policy approval (doc §14) - no matching pre-authorized playbook entry.");
        }

        var autoExecutable = level switch
        {
            ResponseLevel.Observe => true,
            ResponseLevel.Enrich => policy.Engines.AnomalyEngineEnabled || policy.Engines.RuleEngineEnabled,
            ResponseLevel.Restrict => policy.Engines.AutoContainmentEnabled,
            ResponseLevel.Contain or ResponseLevel.EnterpriseResponse => policy.Engines.AutoContainmentEnabled && !requiresApproval,
            _ => false,
        };

        if (!autoExecutable && level >= ResponseLevel.Restrict)
        {
            rationale.Add(policy.Engines.AutoContainmentEnabled
                ? "Blocked pending human approval."
                : "AutoContainmentEnabled is off in the current policy - action will be queued for manual/GUI-triggered execution.");
        }

        return new ResponseDecision
        {
            HostId = risk.HostId,
            Level = level,
            RequiresHumanApproval = requiresApproval,
            IsAutoExecutable = autoExecutable,
            Rationale = rationale,
            MatchedPlaybookActionId = matchedEntry?.ActionId,
        };
    }

    private static ResponseLevel LevelForScore(double score, ResponseThresholds t)
    {
        if (score >= t.EnterpriseResponseAt) return ResponseLevel.EnterpriseResponse;
        if (score >= t.ContainAt) return ResponseLevel.Contain;
        if (score >= t.RestrictAt) return ResponseLevel.Restrict;
        if (score >= t.EnrichAt) return ResponseLevel.Enrich;
        return ResponseLevel.Observe;
    }

    /// <summary>True when every non-autonomy component is negligible - i.e. adaptation-speed is the only thing elevating risk.</summary>
    private static bool IsAutonomyDominated(HostRiskBreakdown risk)
    {
        const double negligible = 0.15;
        return risk.AutonomyScore >= 0.5 &&
               risk.ProcessBehavior < negligible &&
               risk.IdentityRisk < negligible &&
               risk.PersistenceRisk < negligible &&
               risk.CredentialRisk < negligible &&
               risk.LateralMovementRisk < negligible &&
               risk.FileBehavior < negligible;
    }
}
