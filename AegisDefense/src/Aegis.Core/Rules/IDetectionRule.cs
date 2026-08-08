using Aegis.Core.Events;
using Aegis.Core.Features;

namespace Aegis.Core.Rules;

/// <summary>Everything one rule needs to decide whether it fires. Deliberately just data - no I/O, no side effects, fully unit-testable.</summary>
public sealed record RuleContext(NormalizedEvent Event, FeatureSnapshot Features);

/// <summary>
/// A single deterministic, explainable behavioral rule (doc §8 "Multi-Engine Detection" -
/// "Rule engine: known dangerous combinations and policy violations - deterministic, explainable").
/// Rules must be cheap and side-effect free; the engine may run hundreds of them per event.
/// </summary>
public interface IDetectionRule
{
    string Id { get; }

    string Name { get; }

    RuleFinding? Evaluate(RuleContext context);
}
