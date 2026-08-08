using Aegis.Core.Events;

namespace Aegis.Core.Estimation;

/// <summary>
/// Predicts likely next attacker objectives from the current attack state (doc §13
/// "Predictive Defense"). Uses a small static kill-chain transition table blended with
/// whatever residual probability mass the estimator already has on other states, so a
/// campaign that is genuinely behaving atypically isn't forced back onto the "textbook"
/// path. This is intentionally simple and swappable: WP6 calls for measuring whether
/// pre-emptive monitoring/restriction based on these predictions improves containment,
/// which requires a stable, inspectable baseline to compare against.
/// </summary>
public static class NextObjectivePredictor
{
    // Approximate ATT&CK-style progression. Probabilities are illustrative priors, not
    // measured - doc §22 calls for validating next-objective accuracy experimentally.
    private static readonly Dictionary<AttackState, (AttackState State, double Prob)[]> Transitions = new()
    {
        [AttackState.InitialAccess] = new[] { (AttackState.Execution, 0.6), (AttackState.Persistence, 0.2), (AttackState.DefenseEvasion, 0.2) },
        [AttackState.Execution] = new[] { (AttackState.Persistence, 0.35), (AttackState.DefenseEvasion, 0.3), (AttackState.Discovery, 0.35) },
        [AttackState.Persistence] = new[] { (AttackState.PrivilegeEscalation, 0.4), (AttackState.DefenseEvasion, 0.3), (AttackState.Discovery, 0.3) },
        [AttackState.PrivilegeEscalation] = new[] { (AttackState.CredentialAccess, 0.4), (AttackState.DefenseEvasion, 0.35), (AttackState.Discovery, 0.25) },
        [AttackState.DefenseEvasion] = new[] { (AttackState.CredentialAccess, 0.35), (AttackState.Discovery, 0.35), (AttackState.Persistence, 0.3) },
        [AttackState.CredentialAccess] = new[] { (AttackState.Discovery, 0.3), (AttackState.LateralMovement, 0.5), (AttackState.Persistence, 0.2) },
        [AttackState.Discovery] = new[] { (AttackState.LateralMovement, 0.45), (AttackState.CredentialAccess, 0.35), (AttackState.Collection, 0.2) },
        [AttackState.LateralMovement] = new[] { (AttackState.CredentialAccess, 0.35), (AttackState.Persistence, 0.25), (AttackState.Discovery, 0.4) },
        [AttackState.Collection] = new[] { (AttackState.CommandAndControl, 0.4), (AttackState.Exfiltration, 0.5), (AttackState.LateralMovement, 0.1) },
        [AttackState.CommandAndControl] = new[] { (AttackState.Exfiltration, 0.6), (AttackState.Collection, 0.4) },
        [AttackState.Exfiltration] = new[] { (AttackState.Collection, 0.5), (AttackState.LateralMovement, 0.5) },
        [AttackState.Benign] = Array.Empty<(AttackState, double)>(),
    };

    /// <summary>Doc §13's if/then predictive-defense guidance, exposed so the policy/GUI layer can show operators *why* telemetry or restriction increased.</summary>
    public static string RecommendedPreemptiveAction(AttackState predicted) => predicted switch
    {
        AttackState.LateralMovement => "Increase SMB/WinRM/RDP telemetry and enforce narrower access for the suspect host.",
        AttackState.CredentialAccess => "Increase monitoring around credential-bearing processes and privileged authentication.",
        AttackState.Persistence => "Watch service/task/autorun changes with stricter policy.",
        AttackState.Exfiltration => "Increase egress inspection and apply approved data-loss controls.",
        AttackState.PrivilegeEscalation => "Tighten privilege-assignment auditing and require step-up approval for sensitive rights.",
        AttackState.Discovery => "Increase process-tree and network-enumeration telemetry on the host.",
        _ => "Continue standard observation.",
    };

    public static IReadOnlyList<(AttackState State, double Probability)> Predict(
        AttackState current, IReadOnlyDictionary<AttackState, double> currentDistribution, int topK = 3)
    {
        if (current == AttackState.Benign || !Transitions.TryGetValue(current, out var priors))
        {
            return Array.Empty<(AttackState, double)>();
        }

        var blended = new Dictionary<AttackState, double>();
        foreach (var (state, prob) in priors)
        {
            currentDistribution.TryGetValue(state, out var residual);
            blended[state] = prob * 0.7 + residual * 0.3;
        }

        // Any state with meaningful residual probability that isn't already in the prior
        // table still deserves a mention - the campaign may be diverging from the textbook path.
        foreach (var kv in currentDistribution)
        {
            var state = kv.Key;
            var prob = kv.Value;
            if (state == current || blended.ContainsKey(state) || prob < 0.05) continue;
            blended[state] = prob * 0.3;
        }

        return blended
            .OrderByDescending(kv => kv.Value)
            .Take(topK)
            .Select(kv => (kv.Key, kv.Value))
            .ToList();
    }
}
