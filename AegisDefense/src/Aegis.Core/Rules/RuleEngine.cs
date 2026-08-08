namespace Aegis.Core.Rules;

/// <summary>
/// Runs the configured set of <see cref="IDetectionRule"/>s against one event and returns
/// every finding. A single misbehaving rule cannot take the whole engine down: exceptions
/// are caught per-rule so one bad regex or null-ref never blinds the rest of the pipeline.
/// </summary>
public sealed class RuleEngine
{
    private readonly IReadOnlyList<IDetectionRule> _rules;

    public RuleEngine(IReadOnlyList<IDetectionRule>? rules = null)
    {
        _rules = rules ?? BuiltInRules.All;
    }

    public IReadOnlyList<RuleFinding> Evaluate(RuleContext context)
    {
        List<RuleFinding>? findings = null;
        foreach (var rule in _rules)
        {
            RuleFinding? finding;
            try
            {
                finding = rule.Evaluate(context);
            }
            catch (Exception)
            {
                // A rule throwing is a bug in that rule, not grounds to stop detecting everything else.
                // Production wiring should log this via the host's diagnostic sink.
                continue;
            }

            if (finding is null) continue;
            (findings ??= new List<RuleFinding>()).Add(finding);
        }

        return findings ?? (IReadOnlyList<RuleFinding>)Array.Empty<RuleFinding>();
    }
}
