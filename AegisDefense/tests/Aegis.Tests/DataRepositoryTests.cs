using Aegis.Core.Deception;
using Aegis.Core.Events;
using Aegis.Core.Integrity;
using Aegis.Core.Patching;
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
    public async Task AlertRepository_ReUpsert_PersistsGrownEvidence()
    {
        // Regression test for a real bug: the ON CONFLICT clause used to omit
        // evidence_event_ids_json/evidence_summary_json/estimated_state, so re-upserting an
        // existing alert (the "coalesce repeated detections into one alert" path in
        // DefenseEngine) silently dropped the merged evidence on every write.
        var repo = new AlertRepository(_db);
        var alert = new Alert { HostId = "host-1", Title = "High action frequency", Source = "AEG-001" };
        alert.EvidenceEventIds.Add(Guid.NewGuid());
        alert.EvidenceSummary.Add("first occurrence");
        await repo.UpsertAsync(alert);

        alert.EvidenceEventIds.Add(Guid.NewGuid());
        alert.EvidenceSummary.Add("second occurrence");
        alert.EstimatedState = AttackState.LateralMovement;
        await repo.UpsertAsync(alert);

        var reloaded = Assert.Single(await repo.QueryAsync(hostId: "host-1"));
        Assert.Equal(2, reloaded.EvidenceEventIds.Count);
        Assert.Equal(2, reloaded.EvidenceSummary.Count);
        Assert.Equal(AttackState.LateralMovement, reloaded.EstimatedState);
    }

    [Fact]
    public async Task AlertRepository_FindRecentOpenAlert_FindsMatchWithinWindow()
    {
        var repo = new AlertRepository(_db);
        var now = DateTimeOffset.UtcNow;
        var alert = new Alert { HostId = "host-1", Title = "High action frequency", Source = "AEG-001", CreatedAt = now };
        await repo.UpsertAsync(alert);

        var found = await repo.FindRecentOpenAlertAsync("host-1", "AEG-001", TimeSpan.FromMinutes(5), now.AddMinutes(3));

        Assert.NotNull(found);
        Assert.Equal(alert.AlertId, found!.AlertId);
    }

    [Fact]
    public async Task AlertRepository_FindRecentOpenAlert_MatchesAcrossMixedTimezoneOffsets()
    {
        // Regression test for a real bug: alerts are stored via DateTimeOffset.UtcNow
        // (offset +00:00), but two collectors (PowerShellScriptBlock, SecurityEventLog) used
        // to derive NormalizedEvent.Timestamp from EventRecord.TimeCreated without normalizing
        // it to UTC first, so on a host with a non-zero local UTC offset those events' evt.Timestamp
        // (e.g. +03:00) would fail to match against alerts' UTC-stamped created_at under plain
        // ISO-8601 string comparison, even for events genuinely seconds apart - confirmed on
        // real Windows hardware (UTC+3), not theoretical. This test passes an `asOf` in a
        // non-UTC offset to lock in that the lookup still matches correctly regardless.
        var repo = new AlertRepository(_db);
        var now = DateTimeOffset.UtcNow;
        var alert = new Alert { HostId = "host-1", Title = "High action frequency", Source = "AEG-001", CreatedAt = now };
        await repo.UpsertAsync(alert);

        var asOfInLocalOffset = now.AddMinutes(1).ToOffset(TimeSpan.FromHours(3));
        var found = await repo.FindRecentOpenAlertAsync("host-1", "AEG-001", TimeSpan.FromMinutes(5), asOfInLocalOffset);

        Assert.NotNull(found);
        Assert.Equal(alert.AlertId, found!.AlertId);
    }

    [Fact]
    public async Task AlertRepository_FindRecentOpenAlert_IgnoresResolvedAlerts()
    {
        var repo = new AlertRepository(_db);
        var now = DateTimeOffset.UtcNow;
        var alert = new Alert { HostId = "host-1", Title = "High action frequency", Source = "AEG-001", CreatedAt = now };
        await repo.UpsertAsync(alert);
        await repo.UpdateStatusAsync(alert.AlertId, AlertStatus.Resolved);

        var found = await repo.FindRecentOpenAlertAsync("host-1", "AEG-001", TimeSpan.FromMinutes(5), now.AddMinutes(1));

        Assert.Null(found);
    }

    [Fact]
    public async Task AlertRepository_FindRecentOpenAlert_IgnoresAlertsOutsideWindow()
    {
        var repo = new AlertRepository(_db);
        var now = DateTimeOffset.UtcNow;
        var alert = new Alert { HostId = "host-1", Title = "High action frequency", Source = "AEG-001", CreatedAt = now };
        await repo.UpsertAsync(alert);

        var found = await repo.FindRecentOpenAlertAsync("host-1", "AEG-001", TimeSpan.FromMinutes(5), now.AddMinutes(10));

        Assert.Null(found);
    }

    [Fact]
    public async Task AlertRepository_FindRecentOpenAlert_IgnoresDifferentHostOrSource()
    {
        var repo = new AlertRepository(_db);
        var now = DateTimeOffset.UtcNow;
        var alert = new Alert { HostId = "host-1", Title = "High action frequency", Source = "AEG-001", CreatedAt = now };
        await repo.UpsertAsync(alert);

        Assert.Null(await repo.FindRecentOpenAlertAsync("host-2", "AEG-001", TimeSpan.FromMinutes(5), now.AddMinutes(1)));
        Assert.Null(await repo.FindRecentOpenAlertAsync("host-1", "AEG-008", TimeSpan.FromMinutes(5), now.AddMinutes(1)));
    }

    [Fact]
    public async Task AlertRepository_GetById_ReturnsMatchingAlert_NullWhenMissing()
    {
        // GetByIdAsync backs DefenseEngine.ExecuteAlertActionAsync's initial lookup for the
        // GUI's Remove/Quarantine/Ignore buttons - it needs the exact alert, not a filtered list.
        var repo = new AlertRepository(_db);
        var alert = new Alert { HostId = "host-1", Title = "High action frequency", Source = "AEG-001" };
        await repo.UpsertAsync(alert);

        var found = await repo.GetByIdAsync(alert.AlertId);
        Assert.NotNull(found);
        Assert.Equal(alert.AlertId, found!.AlertId);

        Assert.Null(await repo.GetByIdAsync(Guid.NewGuid()));
    }

    [Fact]
    public async Task EventRepository_GetByIds_ReturnsOnlyRequestedEvents_EmptyForEmptyInput()
    {
        // GetByIdsAsync backs the remediation pipeline's evidence-event lookup
        // (DefenseEngine.RemediateFromEvidenceAsync resolves an alert's EvidenceEventIds back
        // into full NormalizedEvents to find the process/file/artifact/destination to act on).
        var repo = new EventRepository(_db);
        var e1 = new NormalizedEvent { EventId = Guid.NewGuid(), Timestamp = DateTimeOffset.UtcNow, HostId = "host-1", ActionType = ActionType.ProcessCreate, ObjectType = ObjectType.Process, Result = ActionResult.Success };
        var e2 = new NormalizedEvent { EventId = Guid.NewGuid(), Timestamp = DateTimeOffset.UtcNow, HostId = "host-1", ActionType = ActionType.ProcessCreate, ObjectType = ObjectType.Process, Result = ActionResult.Success };
        var e3 = new NormalizedEvent { EventId = Guid.NewGuid(), Timestamp = DateTimeOffset.UtcNow, HostId = "host-1", ActionType = ActionType.ProcessCreate, ObjectType = ObjectType.Process, Result = ActionResult.Success };
        await repo.InsertAsync(e1);
        await repo.InsertAsync(e2);
        await repo.InsertAsync(e3);

        var found = await repo.GetByIdsAsync(new[] { e1.EventId, e3.EventId });
        Assert.Equal(2, found.Count);
        Assert.Contains(found, e => e.EventId == e1.EventId);
        Assert.Contains(found, e => e.EventId == e3.EventId);
        Assert.DoesNotContain(found, e => e.EventId == e2.EventId);

        Assert.Empty(await repo.GetByIdsAsync(Array.Empty<Guid>()));
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

    [Fact]
    public async Task EventRepository_PersistsAndVerifiesHashChain()
    {
        var repo = new EventRepository(_db);
        var key = EventChainSigner.GenerateKey();
        var prevHash = EventChainSigner.GenesisHash;

        for (var i = 0; i < 5; i++)
        {
            var evt = new NormalizedEvent
            {
                EventId = Guid.NewGuid(),
                Timestamp = DateTimeOffset.UtcNow.AddSeconds(i),
                HostId = "host-1",
                ActionType = ActionType.ProcessCreate,
                CommandLine = $"cmd-{i}",
            };
            var hash = EventChainSigner.ComputeLink(key, i, prevHash, evt);
            await repo.InsertAsync(evt, sequence: i, chainHash: hash, prevChainHash: prevHash);
            prevHash = hash;
        }

        var lastLink = await repo.GetLastChainLinkAsync();
        Assert.NotNull(lastLink);
        Assert.Equal(4, lastLink!.Value.Sequence);
        Assert.Equal(prevHash, lastLink.Value.ChainHash);

        var chain = await repo.GetChainAsync();
        Assert.Equal(5, chain.Count);
        var result = EventChainVerifier.Verify(key, chain);
        Assert.True(result.Valid);
    }

    [Fact]
    public async Task EventRepository_PruneOlderThan_RemovesOnlyStaleEvents()
    {
        var repo = new EventRepository(_db);
        var old = new NormalizedEvent { EventId = Guid.NewGuid(), Timestamp = DateTimeOffset.UtcNow.AddDays(-30), HostId = "host-1", ActionType = ActionType.ProcessCreate };
        var recent = new NormalizedEvent { EventId = Guid.NewGuid(), Timestamp = DateTimeOffset.UtcNow, HostId = "host-1", ActionType = ActionType.ProcessCreate };

        await repo.InsertAsync(old);
        await repo.InsertAsync(recent);

        var deleted = await repo.PruneOlderThanAsync(DateTimeOffset.UtcNow.AddDays(-7));

        Assert.Equal(1, deleted);
        var remaining = await repo.QueryAsync("host-1");
        Assert.Single(remaining);
        Assert.Equal(recent.EventId, remaining[0].EventId);
    }

    [Fact]
    public async Task PatchPlanRepository_RoundTrips_MutatedPlan_IncludingInternalSetterFields()
    {
        // PatchRolloutPlan.Stage/CurrentRingIndex/MitigationInPlace have internal setters
        // (only the orchestrator should mutate a plan) but still need to survive a JSON
        // round-trip through Aegis.Data, a different assembly - this locks in that
        // [JsonInclude] actually makes that work, not just that the repository plumbing compiles.
        var repo = new PatchPlanRepository(_db);
        var orchestrator = new PatchRolloutOrchestrator();
        var plan = new PatchRolloutPlan
        {
            Component = "OpenSSL 3.0",
            VendorAdvisoryReference = "CVE-2025-TEST",
            Rings = new List<RingDefinition>
            {
                new() { Name = "canary", TargetHostCount = 1 },
                new() { Name = "everyone", TargetHostCount = 500 },
            },
        };
        orchestrator.ApplyTemporaryMitigation(plan, "immediate exploitation risk");
        orchestrator.BeginCanaryTesting(plan, "vendor patch available");
        orchestrator.RecordCanaryHealthCheck(plan, HealthCheckResult.Healthy());
        orchestrator.BeginRingDeployment(plan, "canary validated");

        await repo.UpsertAsync(plan);
        var roundTripped = await repo.GetAsync(plan.PlanId);

        Assert.NotNull(roundTripped);
        Assert.Equal(PatchRolloutStage.RingDeployment, roundTripped!.Stage);
        Assert.Equal(0, roundTripped.CurrentRingIndex);
        Assert.True(roundTripped.MitigationInPlace);
        Assert.Equal(plan.Component, roundTripped.Component);
        Assert.Equal(2, roundTripped.Rings.Count);
        Assert.Equal(4, roundTripped.History.Count);
    }

    [Fact]
    public async Task PatchPlanRepository_ListAsync_ReturnsAllStoredPlans()
    {
        var repo = new PatchPlanRepository(_db);
        var planA = new PatchRolloutPlan { Component = "A", VendorAdvisoryReference = "adv-a", Rings = Array.Empty<RingDefinition>() };
        var planB = new PatchRolloutPlan { Component = "B", VendorAdvisoryReference = "adv-b", Rings = Array.Empty<RingDefinition>() };

        await repo.UpsertAsync(planA);
        await repo.UpsertAsync(planB);

        var all = await repo.ListAsync();

        Assert.Equal(2, all.Count);
        Assert.Contains(all, p => p.Component == "A");
        Assert.Contains(all, p => p.Component == "B");
    }
}
