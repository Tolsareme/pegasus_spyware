using Aegis.Core.Fleet;
using Xunit;

namespace Aegis.Tests;

public class FleetCorrelationStoreTests
{
    private static FleetHeartbeat Heartbeat(string hostId, DateTimeOffset at, params string[] ruleIds) => new()
    {
        HostId = hostId,
        Timestamp = at,
        RuleIdsFired = ruleIds,
        TopAttackState = "Discovery",
        RiskScore = 42,
    };

    [Fact]
    public void GetCorrelation_CountsDistinctHosts_PerRule()
    {
        var store = new FleetCorrelationStore();
        var now = DateTimeOffset.UtcNow;

        store.RecordHeartbeat(Heartbeat("host-1", now, "AEG-002", "AEG-014"));
        store.RecordHeartbeat(Heartbeat("host-2", now, "AEG-002"));
        store.RecordHeartbeat(Heartbeat("host-3", now, "AEG-006"));

        var correlation = store.GetCorrelation(now);

        Assert.Equal(2, correlation.DistinctHostsByRuleId["AEG-002"]);
        Assert.Equal(1, correlation.DistinctHostsByRuleId["AEG-014"]);
        Assert.Equal(1, correlation.DistinctHostsByRuleId["AEG-006"]);
    }

    [Fact]
    public void GetCorrelation_DoesNotDoubleCount_SameHostFiringSameRuleTwice()
    {
        var store = new FleetCorrelationStore();
        var now = DateTimeOffset.UtcNow;

        store.RecordHeartbeat(Heartbeat("host-1", now, "AEG-002"));
        store.RecordHeartbeat(Heartbeat("host-1", now.AddSeconds(30), "AEG-002"));

        var correlation = store.GetCorrelation(now.AddSeconds(30));

        Assert.Equal(1, correlation.DistinctHostsByRuleId["AEG-002"]);
    }

    [Fact]
    public void GetCorrelation_ExpiresEntries_OutsideWindow()
    {
        var store = new FleetCorrelationStore(window: TimeSpan.FromMinutes(5));
        var now = DateTimeOffset.UtcNow;

        store.RecordHeartbeat(Heartbeat("host-1", now, "AEG-002"));

        var correlation = store.GetCorrelation(now.AddMinutes(10));

        Assert.False(correlation.DistinctHostsByRuleId.ContainsKey("AEG-002"));
    }

    [Fact]
    public void GetHostStatuses_ReflectsMostRecentHeartbeatPerHost()
    {
        var store = new FleetCorrelationStore();
        var now = DateTimeOffset.UtcNow;

        store.RecordHeartbeat(Heartbeat("host-1", now, "AEG-002") with { RiskScore = 10 });
        store.RecordHeartbeat(Heartbeat("host-1", now.AddSeconds(10), "AEG-002") with { RiskScore = 90, TopAttackState = "Exfiltration" });

        var statuses = store.GetHostStatuses();

        var status = Assert.Single(statuses);
        Assert.Equal(90, status.RiskScore);
        Assert.Equal("Exfiltration", status.TopAttackState);
    }

    [Fact]
    public void GetHostStatuses_ListsMultipleHosts_NewestFirst()
    {
        var store = new FleetCorrelationStore();
        var now = DateTimeOffset.UtcNow;

        store.RecordHeartbeat(Heartbeat("host-1", now));
        store.RecordHeartbeat(Heartbeat("host-2", now.AddSeconds(5)));

        var statuses = store.GetHostStatuses();

        Assert.Equal(2, statuses.Count);
        Assert.Equal("host-2", statuses[0].HostId);
    }
}
