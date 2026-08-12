using Aegis.Core.Anomaly;
using Aegis.Core.Deception;
using Aegis.Core.Diagnostics;
using Aegis.Core.Estimation;
using Aegis.Core.Events;
using Aegis.Core.Features;
using Aegis.Core.Fleet;
using Aegis.Core.Graph;
using Aegis.Core.Integrity;
using Aegis.Core.Patching;
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
    private readonly PatchPlanRepository _patchPlans;
    private readonly PolicyTrustStore _trustStore;
    private readonly IResponseExecutor _responseExecutor;
    private readonly CollectorHost _collectors;

    private readonly DeceptionManager _deception = new();
    private readonly IDecoyMaterializer _decoyMaterializer;
    private readonly RuleEngine _ruleEngine = new();
    private readonly AttackStateGraph _graph = new();
    private readonly AttackStateEstimator _stateEstimator = new();
    private readonly ResponsePolicyEngine _responsePolicyEngine = new();
    private readonly PatchRolloutOrchestrator _patchOrchestrator = new();
    private readonly IProcessBaseline _baseline = new InMemoryProcessBaseline();
    private readonly IAnomalyModel _anomalyModel = new StatisticalAnomalyModel();

    /// <summary>An anomaly score at or above this level, on its own, is enough to raise an alert even with zero rule findings - otherwise the "statistical/ML engine" (doc §8) could never independently catch anything the deterministic rules missed.</summary>
    private const double AnomalyOnlyAlertThreshold = 0.6;

    /// <summary>How long a still-open alert for the same (host, rule-set) pair keeps absorbing
    /// new evidence before a fresh occurrence gets its own alert instead. Confirmed necessary
    /// via live Windows testing: without this, a rule whose condition stays true across a
    /// sustained burst of events (e.g. a sustained high event rate) creates a brand-new alert
    /// - and, worse, a brand-new response decision with no idempotency guard of its own, see
    /// DecideAndActAsync - for literally every single qualifying event.</summary>
    private static readonly TimeSpan AlertCoalesceWindow = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Guards the find-existing-alert -&gt; merge-or-create -&gt; upsert sequence in
    /// HandleEventAsync. Confirmed necessary via live Windows testing: collectors call
    /// HandleEventAsync concurrently (CollectorHost fire-and-forgets each event, no
    /// serialization - see its own class doc), so during a real burst many events can each
    /// check "does an open alert already exist?" before *any* of them has finished creating
    /// one - a classic check-then-act race that let the alert-flooding bug survive the first
    /// coalescing fix attempt. A plain `lock` can't wrap the `await`s this critical section
    /// needs, hence SemaphoreSlim rather than the `object`+`lock` pattern used elsewhere in
    /// this class (_chainLock/_profileLock, whose critical sections stay synchronous).
    /// </summary>
    private readonly SemaphoreSlim _alertCoalesceLock = new(1, 1);
    private readonly Dictionary<string, HostBehaviorProfile> _hostProfiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _profileLock = new();

    private readonly byte[] _chainKey;
    private readonly object _chainLock = new();
    private long _chainSequence;
    private string _chainPrevHash = EventChainSigner.GenesisHash;

    private ISiemForwarder _siemForwarder = new NullSiemForwarder();
    private IFleetClient _fleetClient = new NullFleetClient();
    private FleetCorrelationSnapshot? _lastCorrelation;
    private Timer? _retentionTimer;
    private Timer? _fleetTimer;

    private DefensePolicy _activePolicy = DefensePolicy.CreateDefault("service-startup-default");
    public DateTimeOffset StartedAt { get; } = DateTimeOffset.UtcNow;

    public string HostId => _collectors.HostId;

    public DefenseEngine(IAegisLogger logger, AegisDatabase db, IResponseExecutor responseExecutor, PolicyTrustStore trustStore, byte[] chainKey, IDecoyMaterializer? decoyMaterializer = null)
    {
        _logger = logger;
        _db = db;
        _events = new EventRepository(db);
        _alerts = new AlertRepository(db);
        _policies = new PolicyRepository(db);
        _vulnerabilities = new VulnerabilityRepository(db);
        _decoyStore = new DecoyRepository(db);
        _approvals = new ApprovalRepository(db);
        _patchPlans = new PatchPlanRepository(db);
        _trustStore = trustStore;
        _responseExecutor = responseExecutor;
        _collectors = new CollectorHost(logger);
        _chainKey = chainKey;
        _decoyMaterializer = decoyMaterializer ?? new NullDecoyMaterializer();
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
        ApplyFleetSettings(_activePolicy.Fleet);
        _retentionTimer = new Timer(_ => _ = RunRetentionAsync(), null, TimeSpan.FromMinutes(5), TimeSpan.FromHours(6));

        _collectors.Start(evt => _ = HandleEventAsync(evt));
        _logger.Info(nameof(DefenseEngine), $"Defense engine started for host '{HostId}' (role: {_collectors.HostRole}).");
    }

    public void Stop()
    {
        _collectors.Stop();
        _retentionTimer?.Dispose();
        _fleetTimer?.Dispose();
        (_fleetClient as IDisposable)?.Dispose();
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

    private void ApplyFleetSettings(FleetSettings settings)
    {
        (_fleetClient as IDisposable)?.Dispose();
        _fleetTimer?.Dispose();
        _fleetTimer = null;
        _lastCorrelation = null;

        if (settings.Enabled && !string.IsNullOrWhiteSpace(settings.HubUrl) && !string.IsNullOrWhiteSpace(settings.ApiKey))
        {
            _fleetClient = new HttpFleetClient(settings.HubUrl!, settings.ApiKey!, _logger);
            var interval = TimeSpan.FromSeconds(Math.Max(15, settings.ReportingIntervalSeconds));
            _fleetTimer = new Timer(_ => _ = RunFleetReportingAsync(), null, TimeSpan.FromSeconds(5), interval);
            _logger.Info(nameof(DefenseEngine), $"Fleet Hub reporting enabled -> {settings.HubUrl} every {interval}.");
        }
        else
        {
            _fleetClient = new NullFleetClient();
        }
    }

    private async Task RunFleetReportingAsync()
    {
        try
        {
            var stateSnapshots = _stateEstimator.GetCurrentStates();
            var topState = stateSnapshots.TryGetValue(HostId, out var state) ? state.ToString() : null;
            var recentAlerts = await _alerts.QueryAsync(HostId, take: 20).ConfigureAwait(false);
            // net48 lacks both StringSplitOptions.TrimEntries and the single-char Split(char, StringSplitOptions)
            // overload (net5.0+ only) - use the char[] overload and trim explicitly instead.
            var recentRuleIds = recentAlerts
                .SelectMany(a => a.Source.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                .Select(s => s.Trim())
                .Distinct()
                .ToList();
            var riskScore = recentAlerts.Count > 0 ? recentAlerts.Max(a => a.RiskBreakdown?.Total ?? 0) : 0;

            await _fleetClient.ReportHeartbeatAsync(new FleetHeartbeat
            {
                HostId = HostId,
                Timestamp = DateTimeOffset.UtcNow,
                RuleIdsFired = recentRuleIds,
                TopAttackState = topState,
                RiskScore = riskScore,
            }).ConfigureAwait(false);

            _lastCorrelation = await _fleetClient.GetCorrelationAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.Warn(nameof(DefenseEngine), $"Fleet reporting cycle failed: {ex.Message}");
        }
    }

    /// <summary>Distinct hosts (other than this one) that recently fired any of these rule IDs, per the last Fleet Hub sync - the real cross-host-coordination signal doc §11's AutonomyScore term needs. 0 (not "unknown") when fleet reporting is disabled or no data has arrived yet, matching FeatureSnapshot's existing default.</summary>
    private int GetCrossHostSimilarHostCount(IReadOnlyList<RuleFinding> findings)
    {
        if (_lastCorrelation is null || findings.Count == 0) return 0;
        var max = 0;
        foreach (var finding in findings)
        {
            if (_lastCorrelation.DistinctHostsByRuleId.TryGetValue(finding.RuleId, out var hostCount))
            {
                max = Math.Max(max, Math.Max(0, hostCount - 1)); // exclude this host itself
            }
        }
        return max;
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

        // A validly-signed policy is not automatically a *current* one: without this check, any
        // older signed policy an attacker can obtain (it's readable via GetPolicy by any
        // authenticated caller, including Analysts, and every version is retained in policy
        // history) could be replayed later to silently downgrade auto-containment/thresholds -
        // without needing the operator's private signing key at all. Signatures only prove
        // authenticity, not freshness, so freshness has to be enforced here.
        if (signedPolicy.Version <= _activePolicy.Version)
        {
            _logger.Warn(nameof(DefenseEngine), $"Rejected policy update '{signedPolicy.PolicyId}' v{signedPolicy.Version} - not newer than the active policy (v{_activePolicy.Version}); possible replay of a stale signed policy.");
            return (false, $"Policy version {signedPolicy.Version} is not newer than the active version {_activePolicy.Version} - rejected to prevent replay of an old signed policy.");
        }

        await _policies.SetActiveAsync(signedPolicy).ConfigureAwait(false);
        _activePolicy = signedPolicy;
        ApplySiemSettings(signedPolicy.Siem);
        ApplyFleetSettings(signedPolicy.Fleet);
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

            // Cross-host coordination (doc §11's AutonomyScore term) requires visibility beyond
            // this one isolated host - fill it in from the last Fleet Hub sync, if any (v2).
            var crossHostCount = GetCrossHostSimilarHostCount(findings);
            if (crossHostCount > 0)
            {
                snapshot = snapshot with { CrossHostSimilarHostCount = crossHostCount };
            }

            var risk = HostRiskCalculator.Compute(snapshot, findings, mlAnomalyScore: anomaly.Score,
                vulnerabilityExposureScore: vulnerabilityExposure, attackSequenceScore: attackSequenceScore,
                weights: _activePolicy.RiskWeights);

            var candidateAlert = BuildAlert(evt, findings, risk, stateSnapshot, anomaly);

            // Coalesce a repeated firing of the same rule(s) against the same host into the
            // existing open alert (new evidence, refreshed severity/confidence) instead of
            // inserting a new row - see AlertCoalesceWindow's doc comment for why this is a
            // correctness fix, not just tidiness: DecideAndActAsync has no idempotency guard,
            // so without this a sustained burst would re-request approval or re-execute a real
            // containment action once per event. The find-then-create sequence is a
            // check-then-act race across concurrently-processed events (see _alertCoalesceLock's
            // doc comment - confirmed via live Windows testing, not theoretical), so it has to
            // run under a lock, not just be logically correct in isolation.
            Alert alert;
            bool isNewAlert;
            await _alertCoalesceLock.WaitAsync().ConfigureAwait(false);
            try
            {
                var existingOpenAlert = await _alerts.FindRecentOpenAlertAsync(candidateAlert.HostId, candidateAlert.Source, AlertCoalesceWindow, evt.Timestamp).ConfigureAwait(false);
                isNewAlert = existingOpenAlert is null;

                if (existingOpenAlert is not null)
                {
                    existingOpenAlert.EvidenceEventIds.Add(evt.EventId);
                    foreach (var line in candidateAlert.EvidenceSummary)
                    {
                        if (!existingOpenAlert.EvidenceSummary.Contains(line)) existingOpenAlert.EvidenceSummary.Add(line);
                    }
                    if (candidateAlert.Severity > existingOpenAlert.Severity) existingOpenAlert.Severity = candidateAlert.Severity;
                    if (candidateAlert.Confidence > existingOpenAlert.Confidence) existingOpenAlert.Confidence = candidateAlert.Confidence;
                    existingOpenAlert.EstimatedState = candidateAlert.EstimatedState;
                    existingOpenAlert.RiskBreakdown = candidateAlert.RiskBreakdown;
                    alert = existingOpenAlert;
                }
                else
                {
                    alert = candidateAlert;
                }

                await _alerts.UpsertAsync(alert).ConfigureAwait(false);
            }
            finally
            {
                _alertCoalesceLock.Release();
            }

            if (isNewAlert)
            {
                await DecideAndActAsync(alert, risk).ConfigureAwait(false);
                await _siemForwarder.ForwardAlertAsync(alert).ConfigureAwait(false);
            }
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

    // --- Alert remediation (v2.3): manual (Remove/Quarantine/Ignore, from the GUI) and
    // automatic (EngineToggles.AutoRemediationEnabled, from DecideAndActAsync) both funnel
    // through RemediateFromEvidenceAsync - neither path invents its own list of what to act
    // on, both act only on artifacts the alert's own evidence events actually identify.

    /// <summary>Executes an operator-chosen action against a specific alert. <see cref="AlertActionKind.Ignore"/>
    /// takes no remediation action at all (just marks the alert FalsePositive); Remove/Quarantine
    /// both act only on the alert's own evidence, never a general sweep of the host.</summary>
    public async Task<(bool Success, string Detail, IReadOnlyList<string> ActionsTaken)> ExecuteAlertActionAsync(Guid alertId, AlertActionKind action)
    {
        var alert = await _alerts.GetByIdAsync(alertId).ConfigureAwait(false);
        if (alert is null) return (false, $"No alert found with id '{alertId}'.", Array.Empty<string>());

        if (action == AlertActionKind.Ignore)
        {
            alert.Status = AlertStatus.FalsePositive;
            await _alerts.UpsertAsync(alert).ConfigureAwait(false);
            _logger.LogAudit(nameof(DefenseEngine), "AlertIgnored", alert.HostId, "Success", $"alert={alertId}");
            return (true, "Alert marked as false positive / ignored - no remediation taken.", Array.Empty<string>());
        }

        var evidenceEvents = await _events.GetByIdsAsync(alert.EvidenceEventIds).ConfigureAwait(false);
        var actionsTaken = await RemediateFromEvidenceAsync(alert.HostId, evidenceEvents, quarantineOnly: action == AlertActionKind.Quarantine).ConfigureAwait(false);

        if (actionsTaken.Count == 0)
        {
            actionsTaken.Add("No actionable artifacts found in this alert's evidence (no process id, executable path, persistence artifact, or destination IP to act on).");
        }

        alert.Status = AlertStatus.Contained;
        alert.AppliedResponse = ResponseLevel.Contain;
        foreach (var line in actionsTaken)
        {
            if (!alert.EvidenceSummary.Contains(line)) alert.EvidenceSummary.Add(line);
        }
        await _alerts.UpsertAsync(alert).ConfigureAwait(false);

        var detail = string.Join(" | ", actionsTaken);
        _logger.LogAudit(nameof(DefenseEngine), "ManualRemediation", alert.HostId, "Success", $"alert={alertId} action={action}: {detail}");
        return (true, detail, actionsTaken);
    }

    /// <summary>
    /// Walks the events that make up an alert's own evidence and takes exactly one bounded
    /// action per distinct artifact identified in them: terminate the process, quarantine the
    /// file it ran from, disable the persistence mechanism it created, block the destination it
    /// talked to. <paramref name="quarantineOnly"/> restricts this to the file-quarantine step
    /// alone (the GUI's lighter-touch "Quarantine" action) - everything else is skipped.
    /// Deliberately reads only what the evidence already contains; this is not a general host
    /// sweep and never invents targets beyond what triggered the alert in the first place.
    /// </summary>
    private async Task<List<string>> RemediateFromEvidenceAsync(string hostId, IReadOnlyList<NormalizedEvent> evidenceEvents, bool quarantineOnly)
    {
        var actions = new List<string>();
        var handledProcessIds = new HashSet<int>();
        var handledFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var handledArtifacts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var handledDestinations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var evt in evidenceEvents)
        {
            if (!quarantineOnly && evt.ProcessId is { } pid && handledProcessIds.Add(pid))
            {
                var result = await _responseExecutor.TerminateProcessAsync(hostId, pid, evt.ImagePath).ConfigureAwait(false);
                actions.Add(AlertEvidenceMarkers.RemediationActionPrefix + (result.Success
                    ? $"Suspended process (PID {pid}, {evt.ImagePath ?? "unknown image"})."
                    : $"Failed to suspend PID {pid}: {result.Detail}"));
            }

            if (evt.ActionType is ActionType.ProcessCreate or ActionType.ScriptExecution && evt.ImagePath is { } imagePath && handledFiles.Add(imagePath))
            {
                var result = await _responseExecutor.QuarantineFileAsync(hostId, imagePath).ConfigureAwait(false);
                actions.Add(AlertEvidenceMarkers.RemediationActionPrefix + (result.Success
                    ? $"Quarantined file: {imagePath}."
                    : $"Could not quarantine '{imagePath}': {result.Detail}"));
            }

            if (!quarantineOnly && EventSemantics.IsPersistenceArtifact(evt.ActionType) && evt.ObjectId is { } artifactId && handledArtifacts.Add(artifactId))
            {
                var result = await _responseExecutor.RemovePersistenceArtifactAsync(hostId, new PersistenceArtifactRef(evt.ActionType, artifactId)).ConfigureAwait(false);
                actions.Add(AlertEvidenceMarkers.RemediationActionPrefix + (result.Success
                    ? $"Removed persistence artifact: {artifactId}."
                    : $"Could not remove persistence artifact '{artifactId}': {result.Detail}"));
            }

            if (!quarantineOnly && evt.DestinationIp is { } destIp && handledDestinations.Add(destIp))
            {
                var result = await _responseExecutor.ApplyFirewallRestrictionAsync(hostId, new FirewallRestriction(
                    RuleName: $"remediation-{destIp.Replace(':', '-')}", Direction: "out", Protocol: "TCP",
                    RemoteAddress: destIp, RemotePort: evt.DestinationPort, Action: "block")).ConfigureAwait(false);
                actions.Add(AlertEvidenceMarkers.RemediationActionPrefix + (result.Success
                    ? $"Blocked network connection to {destIp}{(evt.DestinationPort is { } port ? ":" + port : "")}."
                    : $"Could not block connection to {destIp}: {result.Detail}"));
            }
        }

        return actions;
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

        // Automatic full remediation (v2.3, opt-in via EngineToggles.AutoRemediationEnabled) -
        // layered on top of containment, never a substitute for it, and only reachable at all
        // once the safety gate above (AutoContainmentEnabled + not autonomy-dominated + not
        // requiring approval) has already allowed auto-execution at Contain/EnterpriseResponse.
        // Terminates the offending process, quarantines the file it ran from, disables any
        // persistence artifact, and blocks the flagged destination - exactly the same,
        // evidence-scoped logic as the GUI's manual "Remove" action, just triggered
        // automatically instead of by a click.
        if (decision.Level is ResponseLevel.Contain or ResponseLevel.EnterpriseResponse && _activePolicy.Engines.AutoRemediationEnabled)
        {
            var evidenceEvents = await _events.GetByIdsAsync(alert.EvidenceEventIds).ConfigureAwait(false);
            var remediationActions = await RemediateFromEvidenceAsync(alert.HostId, evidenceEvents, quarantineOnly: false).ConfigureAwait(false);
            if (remediationActions.Count > 0)
            {
                foreach (var line in remediationActions)
                {
                    if (!alert.EvidenceSummary.Contains(line)) alert.EvidenceSummary.Add(line);
                }
                await _alerts.UpsertAsync(alert).ConfigureAwait(false);
                _logger.LogAudit(nameof(DefenseEngine), "AutoRemediation", alert.HostId, "Success", $"alert={alert.AlertId}: {string.Join(" | ", remediationActions)}");
            }
        }
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

    public async Task<IReadOnlyList<Ipc.Contracts.HostInventoryEntry>> GetHostInventoryAsync()
    {
        var since = DateTimeOffset.UtcNow.AddHours(-24);
        var summaries = await _events.GetHostSummariesAsync(since).ConfigureAwait(false);
        var openCounts = await _alerts.GetOpenCountsByHostAsync().ConfigureAwait(false);
        var states = _stateEstimator.GetCurrentStates();

        return summaries
            .Select(kv => new Ipc.Contracts.HostInventoryEntry(
                HostId: kv.Key,
                LastSeen: kv.Value.LastSeen,
                EventCount24h: kv.Value.Count,
                CurrentAttackState: states.TryGetValue(kv.Key, out var state) ? state.ToString() : null,
                OpenAlertCount: openCounts.TryGetValue(kv.Key, out var count) ? count : 0))
            .OrderByDescending(h => h.LastSeen)
            .ToList();
    }
    public (IReadOnlyList<GraphNode> Nodes, IReadOnlyList<GraphEdge> Edges) GetGraphNeighborhood(string nodeId, int maxHops)
    {
        var nodes = _graph.Neighborhood(nodeId, maxHops);
        var nodeIds = new HashSet<string>(nodes.Select(n => n.Id)) { nodeId };
        var edges = _graph.Edges.Where(e => nodeIds.Contains(e.FromId) && nodeIds.Contains(e.ToId)).ToList();
        return (nodes, edges);
    }

    /// <summary>Registers the decoy definition (so access to it is reclassified as a canary hit)
    /// and, best-effort, materializes the real artifact on disk via the configured
    /// <see cref="IDecoyMaterializer"/>. Registration always succeeds if the id is unique even
    /// when materialization doesn't (e.g. an unsupported decoy type, or no materializer
    /// configured) - the returned detail explains what happened so the caller can provision the
    /// artifact manually if needed.</summary>
    public async Task<string?> RegisterDecoyAsync(DecoyResourceDefinition decoy)
    {
        _deception.RegisterDecoy(decoy);
        await _decoyStore.UpsertAsync(decoy).ConfigureAwait(false);

        var result = await _decoyMaterializer.MaterializeAsync(decoy).ConfigureAwait(false);
        if (!result.Success)
            _logger.Warn(nameof(DefenseEngine), $"Decoy '{decoy.Id}' registered, but materialization did not complete: {result.Detail}");
        else
            _logger.Info(nameof(DefenseEngine), $"Decoy '{decoy.Id}' registered and materialized: {result.Detail}");
        return result.Success ? null : result.Detail;
    }

    public async Task<bool> RemoveDecoyAsync(string decoyId)
    {
        var existing = _deception.Decoys.FirstOrDefault(d => d.Id == decoyId);
        var removed = _deception.RemoveDecoy(decoyId);
        await _decoyStore.RemoveAsync(decoyId).ConfigureAwait(false);

        if (existing is not null)
        {
            var result = await _decoyMaterializer.RemoveAsync(existing).ConfigureAwait(false);
            if (!result.Success)
                _logger.Warn(nameof(DefenseEngine), $"Decoy '{decoyId}' unregistered, but artifact removal did not complete: {result.Detail}");
        }
        return removed;
    }

    // --- Patch rollout orchestration (doc §18) -----------------------------------------
    //
    // Every mutating method here loads the plan fresh from storage, applies exactly one
    // orchestrator transition, persists the result, and returns it - there is deliberately
    // no long-lived in-memory plan cache to keep in sync with the database, since this is a
    // low-frequency, operator-driven workflow (unlike the hot event-ingestion path) where
    // "always read the latest persisted state" is simpler and safer than cache invalidation.
    // PatchRolloutOrchestrator itself has no OS integration (see docs/ARCHITECTURE.md) - health
    // checks are supplied by the caller (an operator, or eventually a real monitoring
    // integration), not executed by this engine.

    public async Task<PatchRolloutPlan> CreatePatchPlanAsync(string component, string vendorAdvisoryReference, IReadOnlyList<RingDefinition> rings)
    {
        var plan = new PatchRolloutPlan { Component = component, VendorAdvisoryReference = vendorAdvisoryReference, Rings = rings };
        await _patchPlans.UpsertAsync(plan).ConfigureAwait(false);
        _logger.LogAudit(nameof(DefenseEngine), "PatchPlanCreated", HostId, "Success", $"plan={plan.PlanId} component={component} advisory={vendorAdvisoryReference} rings={rings.Count}");
        return plan;
    }

    public Task<IReadOnlyList<PatchRolloutPlan>> ListPatchPlansAsync() => _patchPlans.ListAsync();

    public Task<PatchRolloutPlan?> GetPatchPlanAsync(Guid planId) => _patchPlans.GetAsync(planId);

    /// <summary>Runs one guarded orchestrator transition against the persisted plan and saves
    /// the result. <paramref name="transition"/> is expected to throw <see cref="InvalidOperationException"/>
    /// (as every <see cref="PatchRolloutOrchestrator"/> method does) if the plan isn't in a
    /// valid stage for the requested transition - that's reported back as a normal failure,
    /// not an unhandled exception, since "wrong stage" is an expected, recoverable caller
    /// error (e.g. a stale GUI view), not a bug.</summary>
    private async Task<(bool Success, string? Error, PatchRolloutPlan? Plan)> ApplyPatchTransitionAsync(Guid planId, Func<PatchRolloutPlan, PatchRolloutPlan> transition, string auditAction)
    {
        var plan = await _patchPlans.GetAsync(planId).ConfigureAwait(false);
        if (plan is null) return (false, $"No patch rollout plan found with id '{planId}'.", null);

        try
        {
            transition(plan);
        }
        catch (InvalidOperationException ex)
        {
            return (false, ex.Message, plan);
        }

        await _patchPlans.UpsertAsync(plan).ConfigureAwait(false);
        _logger.LogAudit(nameof(DefenseEngine), auditAction, HostId, "Success", $"plan={plan.PlanId} stage={plan.Stage}");
        return (true, null, plan);
    }

    public Task<(bool Success, string? Error, PatchRolloutPlan? Plan)> ApplyPatchMitigationAsync(Guid planId, string reason) =>
        ApplyPatchTransitionAsync(planId, p => _patchOrchestrator.ApplyTemporaryMitigation(p, reason), "PatchMitigationApplied");

    public Task<(bool Success, string? Error, PatchRolloutPlan? Plan)> BeginPatchCanaryTestingAsync(Guid planId, string reason) =>
        ApplyPatchTransitionAsync(planId, p => _patchOrchestrator.BeginCanaryTesting(p, reason), "PatchCanaryTestingStarted");

    public Task<(bool Success, string? Error, PatchRolloutPlan? Plan)> RecordPatchCanaryHealthCheckAsync(Guid planId, HealthCheckResult result) =>
        ApplyPatchTransitionAsync(planId, p => _patchOrchestrator.RecordCanaryHealthCheck(p, result), "PatchCanaryHealthCheckRecorded");

    public Task<(bool Success, string? Error, PatchRolloutPlan? Plan)> BeginPatchRingDeploymentAsync(Guid planId, string reason) =>
        ApplyPatchTransitionAsync(planId, p => _patchOrchestrator.BeginRingDeployment(p, reason), "PatchRingDeploymentStarted");

    public Task<(bool Success, string? Error, PatchRolloutPlan? Plan)> RecordPatchRingHealthCheckAsync(Guid planId, HealthCheckResult result) =>
        ApplyPatchTransitionAsync(planId, p => _patchOrchestrator.RecordRingHealthCheck(p, result), "PatchRingHealthCheckRecorded");

    public Task<(bool Success, string? Error, PatchRolloutPlan? Plan)> ClosePatchMitigationAsync(Guid planId, string reason) =>
        ApplyPatchTransitionAsync(planId, p => _patchOrchestrator.CloseMitigationAfterVerification(p, reason), "PatchMitigationClosed");

    public Task<(bool Success, string? Error, PatchRolloutPlan? Plan)> RollbackPatchPlanAsync(Guid planId, string reason) =>
        ApplyPatchTransitionAsync(planId, p => _patchOrchestrator.Rollback(p, reason), "PatchPlanRolledBack");

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
