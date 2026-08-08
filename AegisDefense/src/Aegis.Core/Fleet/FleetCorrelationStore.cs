namespace Aegis.Core.Fleet;

/// <summary>
/// Server-side aggregation behind the Fleet Hub: turns a stream of per-host heartbeats into
/// "how many distinct hosts fired rule X in the last N minutes" and a simple fleet roster.
/// Deliberately plain in-memory state (no database) - the Hub is a correlation cache, not a
/// system of record; if it restarts, hosts just start re-reporting and the window refills
/// within <see cref="_window"/>. Kept in Aegis.Core (not the ASP.NET Core project) so this
/// logic is unit-testable without spinning up a web host.
/// </summary>
public sealed class FleetCorrelationStore
{
    private readonly TimeSpan _window;
    private readonly object _lock = new();
    private readonly List<(string HostId, string RuleId, DateTimeOffset At)> _ruleEvents = new();
    private readonly Dictionary<string, FleetHostStatus> _hostStatus = new(StringComparer.OrdinalIgnoreCase);

    public FleetCorrelationStore(TimeSpan? window = null)
    {
        _window = window ?? TimeSpan.FromMinutes(15);
    }

    public void RecordHeartbeat(FleetHeartbeat heartbeat)
    {
        lock (_lock)
        {
            Prune(heartbeat.Timestamp);

            foreach (var ruleId in heartbeat.RuleIdsFired)
            {
                _ruleEvents.Add((heartbeat.HostId, ruleId, heartbeat.Timestamp));
            }

            _hostStatus[heartbeat.HostId] = new FleetHostStatus
            {
                HostId = heartbeat.HostId,
                LastSeen = heartbeat.Timestamp,
                TopAttackState = heartbeat.TopAttackState,
                RiskScore = heartbeat.RiskScore,
            };
        }
    }

    public FleetCorrelationSnapshot GetCorrelation(DateTimeOffset asOf)
    {
        lock (_lock)
        {
            Prune(asOf);
            var counts = _ruleEvents
                .GroupBy(e => e.RuleId, StringComparer.Ordinal)
                .ToDictionary(g => g.Key, g => g.Select(e => e.HostId).Distinct(StringComparer.OrdinalIgnoreCase).Count());

            return new FleetCorrelationSnapshot { AsOf = asOf, DistinctHostsByRuleId = counts };
        }
    }

    public IReadOnlyList<FleetHostStatus> GetHostStatuses()
    {
        lock (_lock)
        {
            return _hostStatus.Values.OrderByDescending(h => h.LastSeen).ToList();
        }
    }

    private void Prune(DateTimeOffset now)
    {
        var cutoff = now - _window;
        _ruleEvents.RemoveAll(e => e.At < cutoff);
    }
}
