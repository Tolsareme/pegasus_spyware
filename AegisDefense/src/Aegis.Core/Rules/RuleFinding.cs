using Aegis.Core.Events;

namespace Aegis.Core.Rules;

/// <summary>Output of a single deterministic rule firing against one event + feature snapshot.</summary>
public sealed record RuleFinding
{
    public required string RuleId { get; init; }

    public required string Name { get; init; }

    public required string Description { get; init; }

    public AlertSeverity Severity { get; init; } = AlertSeverity.Low;

    public AttackState StateHint { get; init; } = AttackState.Benign;

    /// <summary>0..1 - how confident the rule is that this is truly the described behavior vs. benign coincidence.</summary>
    public double Confidence { get; init; } = 0.7;

    public required Guid TriggeringEventId { get; init; }
}
