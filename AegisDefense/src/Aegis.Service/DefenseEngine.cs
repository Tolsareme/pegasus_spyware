using Aegis.Core.Anomaly;
using Aegis.Core.Deception;
using Aegis.Core.Diagnostics;
using Aegis.Core.Estimation;
using Aegis.Core.Events;
using Aegis.Core.Features;
using Aegis.Core.Graph;
using Aegis.Core.Integrity;
using Aegis.Core.Policy;
using Aegis.Core.Response;
using Aegis.Core.Rules;
using Aegis.Core.Scoring;
using Aegis.Core.Siem;
using Aegis.Core.Vulnerability;
using Aegis.Data;
using Aegis.Sensor;
using System.Threading;

namespace Aegis.Service;

/// <summary>
/// The orchestrator: wires one incoming <see cref="NormalizedEvent"/> through deception
/// reclassification, storage, graph/feature/rule/state engines, composite risk scoring,
/// and finally the policy-bounded response decision - the "Event stream -> graph update ->
/// attack-state inference -> response policy" pipeline from doc §9's diagram. Every engine
/// stage is individually toggleable via the active <see cref="DefensePolicy"/> so the GUI's
/// autonomy controls have real effect without a service restart.
/// </summary>
public sealed class DefenseEngine
{
    private readonly IAegisLogger _logger;
    private readonly AegisDatabase _db;
    private readonly EventRepository _events;
    private readonly AlertRepository _alerts;
    private readonly PolicyRepository _policies;
    private readonly VulnerabilityRepository _vulnerabilities;
    private readonly DecoyRepository _decoyStore;
    private readonly ApprovalRepository _approvals;
    private readonly PolicyTrustStore _trustStore;
    private readonly IResponseExecutor _responseExecutor;
    private readonly CollectorHost _collectors;

    private readonly DeceptionManager _deception = new();
    private readonly RuleEngine _ruleEngine = new();
    private readonly AttackStateGraph _graph = new();
    private readonly AttackStateEstimator _stateEstimator = new();
    private readonly ResponsePolicyEngine _responsePolicyEngine = new();
    private readonly IProcessBaseline _baseline = new InMemoryProcessBaseline();
    private readonly IAnomalyModel _anomalyModel = new StatisticalAnomalyModel();

    /// <summary>An anomaly score at or above this level, on its own, is enough to raise an alert even with zero rule findings - otherwise the "statistical/ML engine" (doc §8) could never independently catch anything the deterministic rules missed.</summary>
    private const double AnomalyOnlyAlertThreshold = 0.6;
    private readonly Dictionary<string, HostBehaviorProfile> _hostProfiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _profileLock = new();

    private readonly byte[] _chainKey;
    private readonly object _chainLock = new();
    private long _chainSequence;
    private string _chainPrevHash = EventChainSigner.GenesisHash;

    private ISiemForwarder _siemForwarder = new NullSiemForwarder();
    private Timer? _retentionTimer;

    private DefensePolicy _activePolicy = DefensePolicy.CreateDefault("service-startup-default");
    public DateTimeOffset StartedAt { get; } = DateTimeOffset.UtcNow;

    public string HostId => _collectors.HostId;

    public DefenseEngine(IAegisLogger logger, AegisDatabase db, IResponseExecutor responseExecutor, PolicyTrustStore trustStore, byte[] chainKey)
    {
        _logger = logger;
        _db = db;
        _events = new EventRepository(db);
        _alerts = new AlertRepository(db);
        _policies = new PolicyRepository(db);
        _vulnerabilities = new VulnerabilityRepository(db);
        _decoyStore = new DecoyRepository(db);
        _approvals = new ApprovalRepository(db);
        _trustStore = trustStore;
        _responseExecutor = responseExecutor;
        _collectors = new CollectorHost(logger);
        _chainKey = chainKey;
    }

    public async Task StartAsync()
    {
        var storedPolicy = await _policies.GetActiveAsync().ConfigureAwait(false);
        if (storedPolicy is not null && _trustStore.Verify(storedPolicy))
        {
            _activePolicy = storedPolicy;
            _logger.Info(nameof(DefenseEngine), $"Loaded active policy '{_activePolicy.PolicyId}' v{_activePolicy.Version} from storage.");
        }
        else
        {
            _logger.Warn(nameof(DefenseEngine), "No verifiable stored policy found - starting with safe built-in defaults (auto-containment OFF).");
        }

        foreach (var decoy in await _decoyStore.ListAsync().ConfigureAwait(false))
        {
            _deception.RegisterDecoy(decoy);
        }

        var lastLink = await _events.GetLastChainLinkAsync().ConfigureAwait(false);
        if (lastLink is { } link)
        {
            _chainSequence = link.Sequence + 1;
            _chainPrevHash = link.ChainHash;
            _logger.Info(nameof(DefenseEngine), $"Resuming event integrity chain at sequence {_chainSequence}.");
        }

        ApplySiemSettings(_activePolicy.Siem);
        _retentionTimer = new Timer(_ => _ = RunRetentionAsync(), null, TimeSpan.FromMinutes(5), TimeSpan.FromHours(6));

        _collectors.Start(evt => _ = HandleEventAsync(evt));
        _logger.Info(nameof(DefenseEngine), $"Defense engine started for host '{HostId}' (role: {_collectors.HostRole}).");
    }

    public void Stop()
    {
        _collectors.Stop();
        _retentionTimer?.Dispose();
    }

    private async Task RunRetentionAsync()
    {
        try
        {
            var days = _activePolicy.EventRetentionDays;
            if (days <= 0) return; // 0 = retention disabled, keep everything

            var cutoff = DateTimeOffset.UtcNow.AddDays(-days);
            var deleted = await _events.PruneOlderThanAsync(cutoff).ConfigureAwait(false);
            if (deleted > 0)
            {
                _logger.LogAudit(nameof(DefenseEngine), "EventRetentionPrune", HostId, "Success", $"Deleted {deleted} raw events older than {days}d (before {cutoff:O}).");
            }
        }
        catch (Exception ex)
        {
            _logger.Error(nameof(DefenseEngine), "Event retention pruning failed.", ex);
        }
    }

    private void ApplySiemSettings(SiemForwardingSettings settings)
    {
        (_siemForwarder as IDisposable)?.Dispose();
        _siemForwarder = settings.Enabled && !string.IsNullOrWhiteSpace(settings.Host)
            ? new CefSyslogForwarder(settings.Host!, settings.Port, settings.UseTcp, settings.DeviceVendor)
            : new NullSiemForwarder();
    }

    /// <summary>Recomputes the entire on-disk event chain and reports the first tampered/missing record, if any (v2 - doc §26 telemetry-poisoning control).</summary>
    public async Task<ChainVerificationResult> VerifyEventChainAsync()
    {
        var chain = await _events.GetChainAsync().ConfigureAwait(false);
        var result = EventChainVerifier.Verify(_chainKey, chain);
        _logger.LogAudit(nameof(DefenseEngine), "VerifyEventChain", HostId, result.Valid ? "Valid" : "TAMPER_DETECTED",
            result.Valid ? $"{result.LinksChecked} links verified." : $"Break at sequence {result.FirstBrokenSequence}: {result.BreakReason}.");
        return result;
    }

    /// <summary>Thread-safe: collectors can call HandleEventAsync concurrently from different collector callbacks, and each event needs a strictly increasing, gap-free sequence number.</summary>
    private (long Sequence, string PreviousHash, string ChainHash) SignNextChainLink(NormalizedEvent evt)
    {
        lock (_chainLock)
        {
            var sequence = _chainSequence;
            var prevHash = _chainPrevHash;
            var chainHash = EventChainSigner.ComputeLink(_chainKey, sequence, prevHash, evt);

            _chainSequence = sequence + 1;
            _chainPrevHash = chainHash;

            return (sequence, prevHash, chainHash);
        }
    }

    public DefensePolicy GetActivePolicy() => _activePolicy;

    public async Task<(bool Accepted, string? Reason)> SetPolicyAsync(DefensePolicy signedPolicy)
    {
        if (!_trustStore.Verify(signedPolicy))
        {
            _logger.Warn(nameof(DefenseEngine), $"Rejected policy update '{signedPolicy.PolicyId}' - signature verification failed.");
            return (false, "Signature verification failed - policy was not applied.");
        }

        await _policies.SetActiveAsync(signedPolicy).ConfigureAwait(false);
        _activePolicy = signedPolicy;
        ApplySiemSettings(signedPolicy.Siem);
        _logger.LogAudit(nameof(DefenseEngine), "PolicyUpdate", HostId, "Success", $"Applied policy '{signedPolicy.PolicyId}' v{signedPolicy.Version} issued by '{signedPolicy.Issuer}'.");
        return (true, null);
    }

    private async Task HandleEventAsync(NormalizedEvent rawEvent)
    {
        try
        {
            var evt = (_activePolicy.Engines.DeceptionEnabled ? _deception.TryClassifyCanaryAccess(rawEvent) : null) ?? rawEvent;

            var (sequence, prevHash, chainHash) = SignNextChainLink(evt);
            await _events.InsertAsync(evt, sequence, chainHash, prevHash).ConfigureAwait(false);

            if (_activePolicy.Engines.GraphEngineEnabled)
            {
                _graph.AddEvent(evt);
            }

            var snapshot = GetProfile(evt.HostId).Ingest(evt);

            var findings = _activePolicy.Engines.RuleEngineEnabled
                ? _ruleEngine.Evaluate(new RuleContext(evt, snapshot))
                : Array.Empty<RuleFinding>();

            // Statistical/ML engine (doc §8): learn this host's normal, then score this
            // observation against it. Observe-then-score means today's point never scores
            // itself as anomalous relative to a baseline it just widened.
            var anomaly = new AnomalyScoreResult(0.0, false, Array.Empty<AnomalyFeatureContribution>());
            if (_activePolicy.Engines.AnomalyEngineEnabled)
            {
                _anomalyModel.Observe(evt.HostId, snapshot);
                anomaly = _anomalyModel.Score(evt.HostId, snapshot);
            }

            AttackStateSnapshot? stateSnapshot = null;
            if (_activePolicy.Engines.AttackStateEstimationEnabled)
            {
                stateSnapshot = _stateEstimator.Update(evt.HostId, evt.Timestamp, findings);
                await ActOnPrediction(evt.HostId, stateSnapshot).ConfigureAwait(false);
            }

            // Nothing rose to alert-worthy - still stored/graphed/estimated/baselined above.
            // A high enough anomaly score can raise an alert on its own (no rule finding
            // required) - otherwise the ML engine could never independently catch anything
            // the deterministic rules missed, defeating the point of running both (doc §8).
            if (findings.Count == 0 && anomaly.Score < AnomalyOnlyAlertThreshold) return;

            var vulnerabilityExposure = await GetVulnerabilityExposureAsync(evt.HostId).ConfigureAwait(false);
            var attackSequenceScore = stateSnapshot is { CurrentState: not AttackState.Benign } s ? s.Confidence : 0.0;

            var risk = HostRiskCalculator.Compute(snapshot, findings, mlAnomalyScore: anomaly.Score,
                vulnerabilityExposureScore: vulnerabilityExposure, attackSequenceScore: attackSequenceScore,
                weights: _activePolicy.RiskWeights);

            var alert = BuildAlert(evt, findings, risk, stateSnapshot, anomaly);
            await _alerts.UpsertAsync(alert).ConfigureAwait(false);

            await DecideAndActAsync(alert, risk).ConfigureAwait(false);

            await _siemForwarder.ForwardAlertAsync(alert).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.Error(nameof(DefenseEngine), $"Unhandled error processing event {rawEvent.EventId} from host {rawEvent.HostId}.", ex);
        }
    }

    private async Task ActOnPrediction(string hostId, AttackStateSnapshot snapshot)
    {
        var topPrediction = snapshot.PredictedNext.Count > 0 ? snapshot.PredictedNext[0] : ((AttackState State, double Probability)?)null;
        if (topPrediction is not { Probability: >= 0.5 } prediction) return;

        // Predictive defense (doc §13): a high-confidence predicted next objective earns a
        // proactive telemetry bump even before risk crosses an alert threshold. This is
        // always safe/reversible, so it does not go through the response policy gate.
        var result = await _responseExecutor.IncreaseTelemetryAsync(hostId, TimeSpan.FromMinutes(30)).ConfigureAwait(false);
        _logger.Info(nameof(DefenseEngine),
            $"Predictive defense: '{prediction.State}' predicted at {prediction.Probability:P0} for host '{hostId}' - {NextObjectivePredictor.RecommendedPreemptiveAction(prediction.State)} (telemetry bump {(result.Success ? "applied" : "failed")}).");
    }

    private async Task<double> GetVulnerabilityExposureAsync(string hostId)
    {
        if (!_activePolicy.Engines.VulnerabilityIntelEnabled) return 0.0;
        var vulns = await _vulnerabilities.QueryAsync(hostId).ConfigureAwait(false);
        return vulns.Count == 0 ? 0.0 : Math.Min(1.0, vulns.Max(v => v.PriorityScore) / 100.0);
    }

    private static Alert BuildAlert(NormalizedEvent evt, IReadOnlyList<RuleFinding> findings, HostRiskBreakdown risk, AttackStateSnapshot? stateSnapshot, AnomalyScoreResult anomaly)
    {
        var topFinding = findings.OrderByDescending(f => f.Severity).ThenByDescending(f => f.Confidence).FirstOrDefault();
        var severity = risk.Total switch
        {
            >= 85 => AlertSeverity.Critical,
            >= 70 => AlertSeverity.High,
            >= 50 => AlertSeverity.Medium,
            _ => AlertSeverity.Low,
        };

        // No rule finding at all means this alert exists purely because the statistical
        // engine flagged a deviation from this host's own learned baseline.
        var title = topFinding?.Name ?? "Statistical deviation from host baseline";
        var source = findings.Count > 0 ? string.Join(",", findings.Select(f => f.RuleId).Distinct()) : "AEG-ML-ANOMALY";
        var estimatedState = stateSnapshot?.CurrentState ?? topFinding?.StateHint ?? AttackState.Benign;

        var alert = new Alert
        {
            HostId = evt.HostId,
            UserId = evt.UserId,
            Title = title,
            Source = source,
            Severity = severity,
            EstimatedState = estimatedState,
            Confidence = risk.Confidence,
            RiskBreakdown = risk,
            RecommendedResponse = ResponseLevel.Observe, // filled in by caller once the policy engine decides
        };

        foreach (var f in findings)
        {
            alert.EvidenceEventIds.Add(f.TriggeringEventId);
            alert.EvidenceSummary.Add($"[{f.RuleId}] {f.Description}");
        }

        if (anomaly.IsWarmedUp && anomaly.TopContributors.Count > 0)
        {
            alert.EvidenceEventIds.Add(evt.EventId);
            var detail = string.Join(", ", anomaly.TopContributors.Select(c => $"{c.Feature}={c.Value:F2} (baseline {c.Mean:F2}±{c.StdDev:F2}, z={c.ZScore:F1})"));
            alert.EvidenceSummary.Add($"[AEG-ML-ANOMALY] score={anomaly.Score:F2} vs. host baseline - {detail}");
        }

        return alert;
    }

    private async Task DecideAndActAsync(Alert alert, HostRiskBreakdown risk)
    {
        var candidatePlaybookAction = risk.Total >= _activePolicy.Thresholds.ContainAt ? "isolate-test-endpoint" : null;
        var decision = _responsePolicyEngine.Decide(risk, _activePolicy, candidatePlaybookAction);

        alert.RecommendedResponse = decision.Level;
        await _alerts.UpsertAsync(alert).ConfigureAwait(false);

        if (decision.Level == ResponseLevel.Observe) return;

        if (!decision.IsAutoExecutable)
        {
            if (decision.RequiresHumanApproval)
            {
                var approval = new PendingApproval
                {
                    HostId = alert.HostId,
                    AlertId = alert.AlertId,
                    RequestedLevel = decision.Level,
                    Rationale = decision.Rationale,
                };
                await _approvals.CreateAsync(approval).ConfigureAwait(false);
                _logger.LogAudit(nameof(DefenseEngine), "ApprovalQueued", alert.HostId, "Pending", $"alert={alert.AlertId} level={decision.Level}");
            }
            return;
        }

        var result = decision.Level switch
        {
            ResponseLevel.Enrich => await _responseExecutor.IncreaseTelemetryAsync(alert.HostId, TimeSpan.FromMinutes(30)).ConfigureAwait(false),
            ResponseLevel.Restrict => await ApplyRestrictionAsync(alert).ConfigureAwait(false),
            ResponseLevel.Contain or ResponseLevel.EnterpriseResponse => await _responseExecutor.IsolateEndpointAsync(alert.HostId, preserveManagementConnectivity: true).ConfigureAwait(false),
            _ => new ResponseActionResult { Success = true, Detail = "No action required." },
        };

        alert.AppliedResponse = decision.Level;
        await _alerts.UpsertAsync(alert).ConfigureAwait(false);
        _logger.LogAudit(nameof(DefenseEngine), "AutoResponse", alert.HostId, result.Success ? "Success" : "Failure", $"alert={alert.AlertId} level={decision.Level} detail={result.Detail}");
    }

    private async Task<ResponseActionResult> ApplyRestrictionAsync(Alert alert)
    {
        var recentEvents = await _events.QueryAsync(alert.HostId, take: 25).ConfigureAwait(false);
        var suspiciousDestination = recentEvents.FirstOrDefault(e => e.DestinationIp is not null);

        if (suspiciousDestination?.DestinationIp is not null)
        {
            return await _responseExecutor.ApplyFirewallRestrictionAsync(alert.HostId, new FirewallRestriction(
                RuleName: $"alert-{alert.AlertId}", Direction: "out", Protocol: "TCP",
                RemoteAddress: suspiciousDestination.DestinationIp, RemotePort: suspiciousDestination.DestinationPort, Action: "block"))
                .ConfigureAwait(false);
        }

        return await _responseExecutor.IncreaseTelemetryAsync(alert.HostId, TimeSpan.FromMinutes(30)).ConfigureAwait(false);
    }

    private HostBehaviorProfile GetProfile(string hostId)
    {
        lock (_profileLock)
        {
            if (!_hostProfiles.TryGetValue(hostId, out var profile))
            {
                profile = new HostBehaviorProfile(hostId, _baseline);
                _hostProfiles[hostId] = profile;
            }
            return profile;
        }
    }

    public async Task<Ipc.Contracts.StatisticsSnapshot> GetStatisticsAsync()
    {
        var since = DateTimeOffset.UtcNow.AddHours(-24);
        var hostIds = await _events.DistinctHostIdsAsync().ConfigureAwait(false);
        var eventsLast24h = await _events.CountSinceAsync(since).ConfigureAwait(false);
        var alertsLast24h = await _alerts.CountSinceAsync(since).ConfigureAwait(false);
        var criticalAlerts = await _alerts.CountSinceAsync(since, AlertSeverity.Critical).ConfigureAwait(false);
        var openAlerts = await _alerts.CountOpenAsync().ConfigureAwait(false);
        var bySeverity = await _alerts.CountBySeverityAsync(since).ConfigureAwait(false);

        var hostStates = _stateEstimator.GetCurrentStates();
        var byState = hostStates.Values
            .GroupBy(s => s.ToString())
            .ToDictionary(g => g.Key, g => g.Count());

        // Proxy for "average risk" until per-host risk history is persisted: share of monitored hosts currently estimated to be in a non-benign attack state.
        var nonBenignHosts = hostStates.Values.Count(s => s != AttackState.Benign);
        var averageRisk = hostIds.Count == 0 ? 0.0 : nonBenignHosts * 100.0 / hostIds.Count;

        var engines = new[]
        {
            new Ipc.Contracts.EngineStatus("RuleEngine", _activePolicy.Engines.RuleEngineEnabled, null),
            new Ipc.Contracts.EngineStatus("AnomalyEngine", _activePolicy.Engines.AnomalyEngineEnabled, null),
            new Ipc.Contracts.EngineStatus("GraphEngine", _activePolicy.Engines.GraphEngineEnabled, $"{_graph.Nodes.Count} nodes / {_graph.Edges.Count} edges"),
            new Ipc.Contracts.EngineStatus("AttackStateEstimation", _activePolicy.Engines.AttackStateEstimationEnabled, null),
            new Ipc.Contracts.EngineStatus("AutonomyScoring", _activePolicy.Engines.AutonomyScoringEnabled, null),
            new Ipc.Contracts.EngineStatus("Deception", _activePolicy.Engines.DeceptionEnabled, $"{_deception.Decoys.Count} decoys"),
            new Ipc.Contracts.EngineStatus("VulnerabilityIntel", _activePolicy.Engines.VulnerabilityIntelEnabled, null),
            new Ipc.Contracts.EngineStatus("AutoContainment", _activePolicy.Engines.AutoContainmentEnabled, null),
            new Ipc.Contracts.EngineStatus("VirtualMitigation", _activePolicy.Engines.VirtualMitigationEnabled, null),
        };

        return new Ipc.Contracts.StatisticsSnapshot(
            AsOf: DateTimeOffset.UtcNow,
            TotalHostsMonitored: hostIds.Count,
            EventsLast24h: eventsLast24h,
            AlertsLast24h: alertsLast24h,
            OpenAlerts: openAlerts,
            CriticalAlerts: criticalAlerts,
            AverageHostRisk: averageRisk,
            Engines: engines,
            ServiceUptime: DateTimeOffset.UtcNow - StartedAt,
            AlertsBySeverity: bySeverity,
            HostsByAttackState: byState);
    }

    // --- Read-side accessors used by the IPC handler ---

    public Task<IReadOnlyList<Alert>> GetAlertsAsync(string? hostId, AlertStatus? status, int take) => _alerts.QueryAsync(hostId, status, take);
    public Task<bool> UpdateAlertStatusAsync(Guid alertId, AlertStatus status) => _alerts.UpdateStatusAsync(alertId, status);
    public Task<IReadOnlyList<NormalizedEvent>> GetEventsAsync(string? hostId, DateTimeOffset? since, int take) => _events.QueryAsync(hostId, since, take);
    public Task<IReadOnlyList<PendingApproval>> GetPendingApprovalsAsync() => _approvals.ListPendingAsync();
    public Task<IReadOnlyList<VulnerabilityPriority>> GetVulnerabilitiesAsync(string? hostId) => _vulnerabilities.QueryAsync(hostId);
    public IReadOnlyList<DecoyResourceDefinition> ListDecoys() => _deception.Decoys;
    public (IReadOnlyList<GraphNode> Nodes, IReadOnlyList<GraphEdge> Edges) GetGraphNeighborhood(string nodeId, int maxHops)
    {
        var nodes = _graph.Neighborhood(nodeId, maxHops);
        var nodeIds = new HashSet<string>(nodes.Select(n => n.Id)) { nodeId };
        var edges = _graph.Edges.Where(e => nodeIds.Contains(e.FromId) && nodeIds.Contains(e.ToId)).ToList();
        return (nodes, edges);
    }

    public async Task RegisterDecoyAsync(DecoyResourceDefinition decoy)
    {
        _deception.RegisterDecoy(decoy);
        await _decoyStore.UpsertAsync(decoy).ConfigureAwait(false);
    }

    public async Task<bool> RemoveDecoyAsync(string decoyId)
    {
        var removed = _deception.RemoveDecoy(decoyId);
        await _decoyStore.RemoveAsync(decoyId).ConfigureAwait(false);
        return removed;
    }

    public async Task<(bool Executed, string? Detail)> ApproveActionAsync(Guid approvalId, string approvedBy)
    {
        var pending = (await _approvals.ListPendingAsync().ConfigureAwait(false)).FirstOrDefault(a => a.ApprovalId == approvalId);
        if (pending is null) return (false, "Approval not found or already resolved.");

        await _approvals.ResolveAsync(approvalId, ApprovalResolution.Approved, approvedBy, null).ConfigureAwait(false);

        var result = pending.RequestedLevel switch
        {
            ResponseLevel.Enrich => await _responseExecutor.IncreaseTelemetryAsync(pending.HostId, TimeSpan.FromMinutes(30)).ConfigureAwait(false),
            ResponseLevel.Restrict or ResponseLevel.Contain or ResponseLevel.EnterpriseResponse =>
                await _responseExecutor.IsolateEndpointAsync(pending.HostId, preserveManagementConnectivity: true).ConfigureAwait(false),
            _ => new ResponseActionResult { Success = true, Detail = "No action required." },
        };

        _logger.LogAudit(nameof(DefenseEngine), "ApprovedResponse", pending.HostId, result.Success ? "Success" : "Failure", $"approval={approvalId} by={approvedBy} detail={result.Detail}");
        return (result.Success, result.Detail);
    }

    public Task<bool> RejectActionAsync(Guid approvalId, string rejectedBy, string? reason) =>
        _approvals.ResolveAsync(approvalId, ApprovalResolution.Rejected, rejectedBy, reason);
}
