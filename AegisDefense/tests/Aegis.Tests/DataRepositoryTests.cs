using Aegis.Core.Deception;
using Aegis.Core.Events;
using Aegis.Core.Policy;
using Aegis.Core.Vulnerability;
using Aegis.Data;
using Xunit;

namespace Aegis.Tests;

public class DataRepositoryTests : IDisposable
{
    private readonly AegisDatabase _db = AegisDatabase.OpenInMemoryForTests();

    public void Dispose() => _db.Dispose();

    [Fact]
    public async Task EventRepository_RoundTrips_AllFields()
    {
        var repo = new EventRepository(_db);
        var evt = new NormalizedEvent
        {
            EventId = Guid.NewGuid(),
            Timestamp = DateTimeOffset.UtcNow,
            HostId = "host-1",
            UserId = "alice",
            ProcessId = 111,
            ParentProcessId = 222,
            ActionType = ActionType.ProcessCreate,
            ObjectType = ObjectType.Process,
            Result = ActionResult.Success,
            Confidence = 0.87,
            CommandLine = "powershell -nop",
            Tags = new Dictionary<string, string> { ["Entropy"] = "7.9" },
        };

        await repo.InsertAsync(evt);
        var results = await repo.QueryAsync(hostId: "host-1");

        var roundTripped = Assert.Single(results);
        Assert.Equal(evt.EventId, roundTripped.EventId);
        Assert.Equal(evt.UserId, roundTripped.UserId);
        Assert.Equal(evt.CommandLine, roundTripped.CommandLine);
        Assert.Equal("7.9", roundTripped.Tags?["Entropy"]);
    }

    [Fact]
    public async Task AlertRepository_UpsertThenUpdateStatus_Persists()
    {
        var repo = new AlertRepository(_db);
        var alert = new Alert
        {
            HostId = "host-1",
            Title = "Test alert",
            Source = "unit-test",
            Severity = AlertSeverity.High,
            EstimatedState = AttackState.CredentialAccess,
        };
        alert.EvidenceEventIds.Add(Guid.NewGuid());

        await repo.UpsertAsync(alert);
        var ok = await repo.UpdateStatusAsync(alert.AlertId, AlertStatus.Acknowledged);
        var results = await repo.QueryAsync(status: AlertStatus.Acknowledged);

        Assert.True(ok);
        var stored = Assert.Single(results);
        Assert.Equal(alert.AlertId, stored.AlertId);
        Assert.Equal(AlertStatus.Acknowledged, stored.Status);
        Assert.Single(stored.EvidenceEventIds);
    }

    [Fact]
    public async Task PolicyRepository_TracksActivePolicy()
    {
        var repo = new PolicyRepository(_db);
        var policy1 = DefensePolicy.CreateDefault("issuer-1");
        var policy2 = DefensePolicy.CreateDefault("issuer-2");

        await repo.SetActiveAsync(policy1);
        await repo.SetActiveAsync(policy2);

        var active = await repo.GetActiveAsync();
        Assert.NotNull(active);
        Assert.Equal("issuer-2", active!.Issuer);

        var history = await repo.GetHistoryAsync();
        Assert.Equal(2, history.Count);
    }

    [Fact]
    public async Task VulnerabilityRepository_OrdersByPriorityDescending()
    {
        var repo = new VulnerabilityRepository(_db);
        var low = VulnerabilityPrioritizer.Prioritize(new VulnerabilityRecord { HostId = "h1", Component = "A", InstalledVersion = "1", SeverityCvss = 2 });
        var high = VulnerabilityPrioritizer.Prioritize(new VulnerabilityRecord { HostId = "h1", Component = "B", InstalledVersion = "1", SeverityCvss = 9, Reachability = ReachabilityLevel.InternetFacing, ObservedExploitationAttempt = true });

        await repo.UpsertAsync(low);
        await repo.UpsertAsync(high);

        var results = await repo.QueryAsync("h1");
        Assert.Equal(2, results.Count);
        Assert.Equal("B", results[0].Record.Component); // highest priority first
    }

    [Fact]
    public async Task DecoyRepository_RegisterAndRemove()
    {
        var repo = new DecoyRepository(_db);
        var decoy = new DecoyResourceDefinition { Id = "d1", Type = DecoyType.File, Location = @"C:\decoys\a.txt", Description = "test" };

        await repo.UpsertAsync(decoy);
        Assert.Single(await repo.ListAsync());

        var removed = await repo.RemoveAsync("d1");
        Assert.True(removed);
        Assert.Empty(await repo.ListAsync());
    }

    [Fact]
    public async Task ApprovalRepository_CreateThenResolve_RemovesFromPendingList()
    {
        var repo = new ApprovalRepository(_db);
        var approval = new PendingApproval
        {
            HostId = "host-1",
            AlertId = Guid.NewGuid(),
            RequestedLevel = ResponseLevel.Contain,
            Rationale = new[] { "risk 90" },
        };

        await repo.CreateAsync(approval);
        Assert.Single(await repo.ListPendingAsync());

        var resolved = await repo.ResolveAsync(approval.ApprovalId, ApprovalResolution.Approved, "operator1", "looked legit");
        Assert.True(resolved);
        Assert.Empty(await repo.ListPendingAsync());
    }
}
