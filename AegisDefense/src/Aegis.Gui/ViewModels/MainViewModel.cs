using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using Aegis.Core.Deception;
using Aegis.Core.Events;
using Aegis.Core.Patching;
using Aegis.Core.Policy;
using Aegis.Core.Vulnerability;
using Aegis.Gui.Services;
using Aegis.Ipc;
using Aegis.Ipc.Contracts;

namespace Aegis.Gui.ViewModels;

public sealed class MainViewModel : ViewModelBase, IDisposable
{
    private readonly PolicySigningKeyManager _keyManager = new();
    private AegisPipeClient? _client;
    private readonly DispatcherTimer _refreshTimer;

    public ObservableCollection<Alert> Alerts { get; } = new();
    public ObservableCollection<NormalizedEvent> Events { get; } = new();
    public ObservableCollection<PendingApproval> PendingApprovals { get; } = new();
    public ObservableCollection<VulnerabilityPriority> Vulnerabilities { get; } = new();
    public ObservableCollection<DecoyResourceDefinition> Decoys { get; } = new();
    public ObservableCollection<HostInventoryEntry> Hosts { get; } = new();
    public ObservableCollection<GraphNodeViewModel> PositionedGraphNodes { get; } = new();
    public ObservableCollection<GraphEdgeViewModel> PositionedGraphEdges { get; } = new();
    public ObservableCollection<PatchRolloutPlan> PatchPlans { get; } = new();

    /// <summary>Raised when a refresh discovers a Critical-severity alert this session hasn't already seen - MainWindow subscribes to surface a tray balloon notification (v2).</summary>
    public event Action<Alert>? NewCriticalAlert;

    private StatisticsSnapshot? _statistics;
    public StatisticsSnapshot? Statistics { get => _statistics; set => SetField(ref _statistics, value); }

    private DefensePolicy? _activePolicy;
    public DefensePolicy? ActivePolicy { get => _activePolicy; set => SetField(ref _activePolicy, value); }

    private string _connectionStatus = "Disconnected";
    public string ConnectionStatus { get => _connectionStatus; set => SetField(ref _connectionStatus, value); }

    private bool _isConnected;
    public bool IsConnected { get => _isConnected; set => SetField(ref _isConnected, value); }

    private string _statusMessage = "Ready.";
    public string StatusMessage { get => _statusMessage; set => SetField(ref _statusMessage, value); }

    public bool HasSigningKey => _keyManager.HasKey;

    private OperatorRole _role = OperatorRole.Administrator;
    /// <summary>Server-confirmed role for this connection (v2 RBAC). Defaults to Administrator optimistically until the first WhoAmI response arrives, since the pipe's ACL already means only a trusted account could connect at all in the pre-RBAC/no-Analyst-group-provisioned case.</summary>
    public OperatorRole Role
    {
        get => _role;
        set
        {
            if (SetField(ref _role, value))
            {
                OnPropertyChanged(nameof(IsAdministrator));
                OnPropertyChanged(nameof(RoleDescription));
            }
        }
    }

    /// <summary>Bound to IsEnabled on every mutating control - the GUI's convenience mirror of the authoritative server-side check in IpcRequestHandler.</summary>
    public bool IsAdministrator => Role == OperatorRole.Administrator;

    public string RoleDescription => Role switch
    {
        OperatorRole.Administrator => "Administrator (full control)",
        OperatorRole.Analyst => "Analyst (read-only)",
        _ => "Unknown",
    };

    private Alert? _selectedAlert;
    public Alert? SelectedAlert { get => _selectedAlert; set => SetField(ref _selectedAlert, value); }

    private PendingApproval? _selectedApproval;
    public PendingApproval? SelectedApproval { get => _selectedApproval; set => SetField(ref _selectedApproval, value); }

    private DecoyResourceDefinition? _selectedDecoy;
    public DecoyResourceDefinition? SelectedDecoy { get => _selectedDecoy; set => SetField(ref _selectedDecoy, value); }

    private string _graphNodeIdInput = "";
    public string GraphNodeIdInput { get => _graphNodeIdInput; set => SetField(ref _graphNodeIdInput, value); }

    private PatchRolloutPlan? _selectedPatchPlan;
    public PatchRolloutPlan? SelectedPatchPlan { get => _selectedPatchPlan; set => SetField(ref _selectedPatchPlan, value); }

    private string _newPatchComponent = "";
    public string NewPatchComponent { get => _newPatchComponent; set => SetField(ref _newPatchComponent, value); }

    private string _newPatchAdvisoryReference = "";
    public string NewPatchAdvisoryReference { get => _newPatchAdvisoryReference; set => SetField(ref _newPatchAdvisoryReference, value); }

    private string _newPatchRingsCsv = "canary:1,everyone:9999";
    public string NewPatchRingsCsv { get => _newPatchRingsCsv; set => SetField(ref _newPatchRingsCsv, value); }

    // --- Trend history (client-side; the service only ever exposes point-in-time statistics) ---
    private const int MaxTrendPoints = 60; // 5 minutes at the 5s refresh interval
    private readonly List<double> _riskHistory = new();
    private readonly List<double> _alertHistory = new();

    private PointCollection _riskTrendPoints = new();
    public PointCollection RiskTrendPoints { get => _riskTrendPoints; private set => SetField(ref _riskTrendPoints, value); }

    private PointCollection _alertTrendPoints = new();
    public PointCollection AlertTrendPoints { get => _alertTrendPoints; private set => SetField(ref _alertTrendPoints, value); }

    public RelayCommand ConnectCommand { get; }
    public RelayCommand RefreshCommand { get; }
    public RelayCommand AckAlertCommand { get; }
    public RelayCommand ContainAlertHostCommand { get; }
    public RelayCommand ApproveCommand { get; }
    public RelayCommand RejectCommand { get; }
    public RelayCommand SavePolicyCommand { get; }
    public RelayCommand GenerateSigningKeyCommand { get; }
    public RelayCommand ExportPublicKeyCommand { get; }
    public RelayCommand RemoveDecoyCommand { get; }
    public RelayCommand VerifyEventChainCommand { get; }
    public RelayCommand LoadGraphCommand { get; }
    public RelayCommand CreatePatchPlanCommand { get; }
    public RelayCommand ApplyPatchMitigationCommand { get; }
    public RelayCommand BeginPatchCanaryTestingCommand { get; }
    public RelayCommand RecordHealthyHealthCheckCommand { get; }
    public RelayCommand RecordUnhealthyHealthCheckCommand { get; }
    public RelayCommand BeginPatchRingDeploymentCommand { get; }
    public RelayCommand ClosePatchMitigationCommand { get; }
    public RelayCommand RollbackPatchPlanCommand { get; }

    private bool _hasCompletedFirstRefresh;

    public MainViewModel()
    {
        ConnectCommand = new RelayCommand(_ => ConnectAsync());
        RefreshCommand = new RelayCommand(_ => RefreshAllAsync());
        AckAlertCommand = new RelayCommand(p => AckAlertAsync(p as Alert));
        ContainAlertHostCommand = new RelayCommand(p => RequestContainmentAsync(p as Alert));
        ApproveCommand = new RelayCommand(p => ApproveAsync(p as PendingApproval));
        RejectCommand = new RelayCommand(p => RejectAsync(p as PendingApproval));
        SavePolicyCommand = new RelayCommand(_ => SavePolicyAsync());
        GenerateSigningKeyCommand = new RelayCommand(_ => GenerateSigningKey());
        ExportPublicKeyCommand = new RelayCommand(_ => ExportPublicKey());
        RemoveDecoyCommand = new RelayCommand(p => RemoveDecoyAsync(p as DecoyResourceDefinition));
        VerifyEventChainCommand = new RelayCommand(_ => VerifyEventChainAsync());
        LoadGraphCommand = new RelayCommand(_ => LoadGraphAsync());
        CreatePatchPlanCommand = new RelayCommand(_ => CreatePatchPlanAsync());
        ApplyPatchMitigationCommand = new RelayCommand(_ => ApplyPatchMitigationAsync());
        BeginPatchCanaryTestingCommand = new RelayCommand(_ => BeginPatchCanaryTestingAsync());
        RecordHealthyHealthCheckCommand = new RelayCommand(_ => RecordPatchHealthCheckAsync(healthy: true));
        RecordUnhealthyHealthCheckCommand = new RelayCommand(_ => RecordPatchHealthCheckAsync(healthy: false));
        BeginPatchRingDeploymentCommand = new RelayCommand(_ => BeginPatchRingDeploymentAsync());
        ClosePatchMitigationCommand = new RelayCommand(_ => ClosePatchMitigationAsync());
        RollbackPatchPlanCommand = new RelayCommand(_ => RollbackPatchPlanAsync());

        _refreshTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _refreshTimer.Tick += async (_, _) => await RefreshAllAsync().ConfigureAwait(true);
    }

    public async Task InitializeAsync()
    {
        await ConnectAsync().ConfigureAwait(true);
        _refreshTimer.Start();
    }

    private async Task ConnectAsync()
    {
        try
        {
            if (_client is not null) await _client.DisposeAsync().ConfigureAwait(true);
            _client = new AegisPipeClient();
            await _client.ConnectAsync().ConfigureAwait(true);
            IsConnected = true;
            ConnectionStatus = "Connected";
            await RefreshAllAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            IsConnected = false;
            ConnectionStatus = $"Disconnected ({ex.Message})";
        }
    }

    private async Task RefreshAllAsync()
    {
        if (_client is null || !_client.IsConnected)
        {
            await ConnectAsync().ConfigureAwait(true);
            if (_client is null || !_client.IsConnected) return;
        }

        try
        {
            var stats = await _client.RequestAsync<GetStatisticsRequest, GetStatisticsResponse>(MessageTypes.GetStatistics, new GetStatisticsRequest()).ConfigureAwait(true);
            Statistics = stats.Statistics;
            RecordTrendPoint(stats.Statistics);

            var alerts = await _client.RequestAsync<GetAlertsRequest, GetAlertsResponse>(MessageTypes.GetAlerts, new GetAlertsRequest(null, null, 200)).ConfigureAwait(true);
            ReplaceAll(Alerts, alerts.Alerts);
            DetectNewCriticalAlerts(alerts.Alerts);

            var hosts = await _client.RequestAsync<GetHostInventoryRequest, GetHostInventoryResponse>(MessageTypes.GetHostInventory, new GetHostInventoryRequest()).ConfigureAwait(true);
            ReplaceAll(Hosts, hosts.Hosts);

            var events = await _client.RequestAsync<GetEventsRequest, GetEventsResponse>(MessageTypes.GetEvents, new GetEventsRequest(null, null, 300)).ConfigureAwait(true);
            ReplaceAll(Events, events.Events);

            var approvals = await _client.RequestAsync<GetPendingApprovalsRequest, GetPendingApprovalsResponse>(MessageTypes.GetPendingApprovals, new GetPendingApprovalsRequest()).ConfigureAwait(true);
            ReplaceAll(PendingApprovals, approvals.Approvals);

            var vulns = await _client.RequestAsync<GetVulnerabilitiesRequest, GetVulnerabilitiesResponse>(MessageTypes.GetVulnerabilities, new GetVulnerabilitiesRequest(null)).ConfigureAwait(true);
            ReplaceAll(Vulnerabilities, vulns.Vulnerabilities);

            var decoys = await _client.RequestAsync<ListDecoysRequest, ListDecoysResponse>(MessageTypes.ListDecoys, new ListDecoysRequest()).ConfigureAwait(true);
            ReplaceAll(Decoys, decoys.Decoys);

            var patchPlans = await _client.RequestAsync<ListPatchPlansRequest, ListPatchPlansResponse>(MessageTypes.ListPatchPlans, new ListPatchPlansRequest()).ConfigureAwait(true);
            ReplaceAll(PatchPlans, patchPlans.Plans);

            var policy = await _client.RequestAsync<GetPolicyRequest, GetPolicyResponse>(MessageTypes.GetPolicy, new GetPolicyRequest()).ConfigureAwait(true);
            ActivePolicy = policy.Policy;

            var whoAmI = await _client.RequestAsync<WhoAmIRequest, WhoAmIResponse>(MessageTypes.WhoAmI, new WhoAmIRequest()).ConfigureAwait(true);
            Role = whoAmI.Role;

            _hasCompletedFirstRefresh = true;
            StatusMessage = $"Refreshed at {DateTimeOffset.Now:T}. Role: {RoleDescription}.";
        }
        catch (Exception ex)
        {
            IsConnected = false;
            ConnectionStatus = $"Disconnected ({ex.Message})";
            StatusMessage = "Refresh failed - service may be stopped or the connection dropped.";
        }
    }

    private async Task AckAlertAsync(Alert? alert)
    {
        if (alert is null || _client is null) return;
        await _client.RequestAsync<UpdateAlertStatusRequest, UpdateAlertStatusResponse>(
            MessageTypes.UpdateAlertStatus, new UpdateAlertStatusRequest(alert.AlertId, AlertStatus.Acknowledged, Environment.UserName)).ConfigureAwait(true);
        await RefreshAllAsync().ConfigureAwait(true);
    }

    private async Task RequestContainmentAsync(Alert? alert)
    {
        if (alert is null) return;
        // Marking Investigating here; actual containment execution is policy-gated server-side
        // and, for anything above Restrict, requires an explicit ApproveAction call below -
        // the GUI never has a shortcut path around the policy engine.
        if (_client is null) return;
        await _client.RequestAsync<UpdateAlertStatusRequest, UpdateAlertStatusResponse>(
            MessageTypes.UpdateAlertStatus, new UpdateAlertStatusRequest(alert.AlertId, AlertStatus.Investigating, Environment.UserName)).ConfigureAwait(true);
        StatusMessage = $"Alert {alert.AlertId} marked Investigating. Check the Approvals tab if containment requires sign-off.";
        await RefreshAllAsync().ConfigureAwait(true);
    }

    private async Task ApproveAsync(PendingApproval? approval)
    {
        if (approval is null || _client is null) return;
        var result = await _client.RequestAsync<ApproveActionRequest, ApproveActionResponse>(
            MessageTypes.ApproveAction, new ApproveActionRequest(approval.ApprovalId, Environment.UserName)).ConfigureAwait(true);
        StatusMessage = result.Executed ? $"Action approved and executed: {result.Detail}" : $"Approval recorded but execution failed: {result.Detail}";
        await RefreshAllAsync().ConfigureAwait(true);
    }

    private async Task RejectAsync(PendingApproval? approval)
    {
        if (approval is null || _client is null) return;
        await _client.RequestAsync<RejectActionRequest, RejectActionResponse>(
            MessageTypes.RejectAction, new RejectActionRequest(approval.ApprovalId, Environment.UserName, "Rejected via console")).ConfigureAwait(true);
        await RefreshAllAsync().ConfigureAwait(true);
    }

    private async Task VerifyEventChainAsync()
    {
        if (_client is null) return;
        try
        {
            var result = await _client.RequestAsync<VerifyEventChainRequest, VerifyEventChainResponse>(
                MessageTypes.VerifyEventChain, new VerifyEventChainRequest()).ConfigureAwait(true);

            StatusMessage = result.Valid
                ? $"Event chain verified: {result.LinksChecked} records, no tampering detected."
                : $"TAMPER DETECTED at sequence {result.FirstBrokenSequence} ({result.BreakReason}) - {result.LinksChecked} records checked before the break.";

            MessageBox.Show(StatusMessage, "Event Chain Integrity",
                MessageBoxButton.OK, result.Valid ? MessageBoxImage.Information : MessageBoxImage.Error);
        }
        catch (Exception ex)
        {
            StatusMessage = $"Chain verification failed: {ex.Message}";
        }
    }

    private async Task RemoveDecoyAsync(DecoyResourceDefinition? decoy)
    {
        if (decoy is null || _client is null) return;
        await _client.RequestAsync<RemoveDecoyRequest, RemoveDecoyResponse>(MessageTypes.RemoveDecoy, new RemoveDecoyRequest(decoy.Id)).ConfigureAwait(true);
        await RefreshAllAsync().ConfigureAwait(true);
    }

    // --- Patch rollout orchestration (doc §18) ---
    // There is no automated health-check integration wired up yet (see docs/ARCHITECTURE.md) -
    // "healthy"/"unhealthy" here is an explicit operator judgment call recorded through the
    // same guarded state machine a real monitoring integration would eventually drive.

    private async Task CreatePatchPlanAsync()
    {
        if (_client is null) return;
        if (string.IsNullOrWhiteSpace(NewPatchComponent) || string.IsNullOrWhiteSpace(NewPatchAdvisoryReference))
        {
            StatusMessage = "Enter a component name and vendor advisory reference before creating a patch plan.";
            return;
        }

        var rings = ParseRings(NewPatchRingsCsv);
        if (rings.Count == 0)
        {
            StatusMessage = "Could not parse rings - use the format 'name:count,name:count' (e.g. 'canary:1,everyone:500').";
            return;
        }

        await _client.RequestAsync<CreatePatchPlanRequest, PatchPlanActionResponse>(
            MessageTypes.CreatePatchPlan, new CreatePatchPlanRequest(NewPatchComponent.Trim(), NewPatchAdvisoryReference.Trim(), rings)).ConfigureAwait(true);
        NewPatchComponent = "";
        NewPatchAdvisoryReference = "";
        StatusMessage = "Patch rollout plan created (stage: Assessed).";
        await RefreshAllAsync().ConfigureAwait(true);
    }

    private static IReadOnlyList<RingDefinition> ParseRings(string csv)
    {
        var rings = new List<RingDefinition>();
        foreach (var token in csv.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = token.Split(':');
            if (parts.Length != 2) continue;
            if (!int.TryParse(parts[1].Trim(), out var count)) continue;
            var name = parts[0].Trim();
            if (name.Length == 0) continue;
            rings.Add(new RingDefinition { Name = name, TargetHostCount = count });
        }
        return rings;
    }

    private async Task ApplyPatchMitigationAsync() =>
        await RunPatchActionAsync(async () => await _client!.RequestAsync<ApplyPatchMitigationRequest, PatchPlanActionResponse>(
            MessageTypes.ApplyPatchMitigation, new ApplyPatchMitigationRequest(SelectedPatchPlan!.PlanId, "Applied via console")).ConfigureAwait(true)).ConfigureAwait(true);

    private async Task BeginPatchCanaryTestingAsync() =>
        await RunPatchActionAsync(async () => await _client!.RequestAsync<BeginPatchCanaryTestingRequest, PatchPlanActionResponse>(
            MessageTypes.BeginPatchCanaryTesting, new BeginPatchCanaryTestingRequest(SelectedPatchPlan!.PlanId, "Started via console")).ConfigureAwait(true)).ConfigureAwait(true);

    private async Task BeginPatchRingDeploymentAsync() =>
        await RunPatchActionAsync(async () => await _client!.RequestAsync<BeginPatchRingDeploymentRequest, PatchPlanActionResponse>(
            MessageTypes.BeginPatchRingDeployment, new BeginPatchRingDeploymentRequest(SelectedPatchPlan!.PlanId, "Started via console")).ConfigureAwait(true)).ConfigureAwait(true);

    private async Task ClosePatchMitigationAsync() =>
        await RunPatchActionAsync(async () => await _client!.RequestAsync<ClosePatchMitigationRequest, PatchPlanActionResponse>(
            MessageTypes.ClosePatchMitigation, new ClosePatchMitigationRequest(SelectedPatchPlan!.PlanId, "Closed via console after verification")).ConfigureAwait(true)).ConfigureAwait(true);

    private async Task RollbackPatchPlanAsync() =>
        await RunPatchActionAsync(async () => await _client!.RequestAsync<RollbackPatchPlanRequest, PatchPlanActionResponse>(
            MessageTypes.RollbackPatchPlan, new RollbackPatchPlanRequest(SelectedPatchPlan!.PlanId, "Rolled back via console")).ConfigureAwait(true)).ConfigureAwait(true);

    private async Task RecordPatchHealthCheckAsync(bool healthy)
    {
        if (SelectedPatchPlan is null || _client is null) return;

        var result = healthy
            ? HealthCheckResult.Healthy()
            : new HealthCheckResult
            {
                ApplicationHealthy = false, ServiceHealthy = false, BootHealthy = true, AuthenticationHealthy = true, NetworkHealthy = true,
                Notes = new[] { "Marked unhealthy via console (manual operator judgment - no automated health probe wired up yet)." },
            };

        if (SelectedPatchPlan.Stage == PatchRolloutStage.CanaryTesting)
        {
            await RunPatchActionAsync(async () => await _client.RequestAsync<RecordPatchCanaryHealthCheckRequest, PatchPlanActionResponse>(
                MessageTypes.RecordPatchCanaryHealthCheck, new RecordPatchCanaryHealthCheckRequest(SelectedPatchPlan.PlanId, result)).ConfigureAwait(true)).ConfigureAwait(true);
        }
        else if (SelectedPatchPlan.Stage == PatchRolloutStage.RingDeployment)
        {
            await RunPatchActionAsync(async () => await _client.RequestAsync<RecordPatchRingHealthCheckRequest, PatchPlanActionResponse>(
                MessageTypes.RecordPatchRingHealthCheck, new RecordPatchRingHealthCheckRequest(SelectedPatchPlan.PlanId, result)).ConfigureAwait(true)).ConfigureAwait(true);
        }
        else
        {
            StatusMessage = $"Plan is at stage '{SelectedPatchPlan.Stage}' - no health check applies here (expected CanaryTesting or RingDeployment).";
        }
    }

    private async Task RunPatchActionAsync(Func<Task<PatchPlanActionResponse>> action)
    {
        if (SelectedPatchPlan is null || _client is null) return;
        try
        {
            var response = await action().ConfigureAwait(true);
            StatusMessage = response.Success
                ? $"Patch plan '{response.Plan?.Component}' now at stage '{response.Plan?.Stage}'."
                : $"Patch plan action rejected: {response.Error}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Patch plan action failed: {ex.Message}";
        }
        await RefreshAllAsync().ConfigureAwait(true);
    }

    private async Task SavePolicyAsync()
    {
        if (ActivePolicy is null || _client is null) return;

        if (!_keyManager.HasKey)
        {
            StatusMessage = "No policy signing key yet - use 'Generate Signing Key' first, then install the exported public key on the service host.";
            return;
        }

        try
        {
            using var rsa = _keyManager.LoadKey();
            ActivePolicy.Version += 1;
            ActivePolicy.IssuedAt = DateTimeOffset.UtcNow;
            ActivePolicy.Issuer = Environment.UserName;
            PolicySignature.Sign(ActivePolicy, rsa);

            var response = await _client.RequestAsync<SetPolicyRequest, SetPolicyResponse>(
                MessageTypes.SetPolicy, new SetPolicyRequest(ActivePolicy)).ConfigureAwait(true);

            StatusMessage = response.Accepted
                ? "Policy applied."
                : $"Policy rejected by service: {response.RejectionReason}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to sign/apply policy: {ex.Message}";
        }
    }

    private void GenerateSigningKey()
    {
        var confirm = MessageBox.Show(
            "This creates a new policy-signing key for this operator account. If a key already exists it will be replaced, and any service trusting the old public key will reject future policy updates until it is re-provisioned. Continue?",
            "Generate Policy Signing Key", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;

        using var rsa = _keyManager.GenerateNewKey();
        OnPropertyChanged(nameof(HasSigningKey));
        StatusMessage = "New signing key generated. Export the public key and install it on the service host to complete provisioning.";
    }

    private void ExportPublicKey()
    {
        if (!_keyManager.HasKey)
        {
            StatusMessage = "Generate a signing key first.";
            return;
        }

        var destination = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "policy-trusted-public.xml");
        using var rsa = _keyManager.LoadKey();
        _keyManager.ExportPublicKeyToFile(rsa, destination);
        StatusMessage = $"Public key exported to {destination}. Copy it to the service host's keys\\policy-trusted-public.xml (see docs/OPERATIONS.md).";
    }

    private static void ReplaceAll<T>(ObservableCollection<T> collection, IReadOnlyList<T> items)
    {
        collection.Clear();
        foreach (var item in items) collection.Add(item);
    }

    // --- Trend charts ---

    private void RecordTrendPoint(StatisticsSnapshot stats)
    {
        _riskHistory.Add(stats.AverageHostRisk);
        _alertHistory.Add(stats.AlertsLast24h);
        if (_riskHistory.Count > MaxTrendPoints) _riskHistory.RemoveAt(0);
        if (_alertHistory.Count > MaxTrendPoints) _alertHistory.RemoveAt(0);

        RiskTrendPoints = BuildSparklinePoints(_riskHistory, maxValue: 100);
        AlertTrendPoints = BuildSparklinePoints(_alertHistory, maxValue: Math.Max(5, _alertHistory.Count == 0 ? 5 : _alertHistory.Max()));
    }

    /// <summary>Maps a value history onto a fixed 400x80 drawing area for a Polyline - a hand-rolled sparkline rather than a charting library dependency, which is plenty for "is this trending up or down".</summary>
    private static PointCollection BuildSparklinePoints(IReadOnlyList<double> values, double maxValue)
    {
        const double width = 400, height = 80;
        var points = new PointCollection();
        if (values.Count == 0) return points;

        var xStep = values.Count <= 1 ? 0 : width / (values.Count - 1);
        var safeMax = maxValue <= 0 ? 1 : maxValue;
        for (var i = 0; i < values.Count; i++)
        {
            var x = i * xStep;
            var y = height - Math.Min(1.0, values[i] / safeMax) * height;
            points.Add(new Point(x, y));
        }
        return points;
    }

    // --- Tray notifications ---

    private readonly HashSet<Guid> _knownCriticalAlertIds = new();

    private void DetectNewCriticalAlerts(IReadOnlyList<Alert> alerts)
    {
        foreach (var alert in alerts.Where(a => a.Severity == AlertSeverity.Critical))
        {
            if (_knownCriticalAlertIds.Add(alert.AlertId) && _hasCompletedFirstRefresh)
            {
                // Only notify for alerts that appeared *after* the console connected - the
                // first refresh seeds the "already known" set silently so a console pointed
                // at a service with existing history doesn't fire a notification storm.
                NewCriticalAlert?.Invoke(alert);
            }
        }
    }

    // --- Attack graph ---

    private async Task LoadGraphAsync()
    {
        if (_client is null || string.IsNullOrWhiteSpace(GraphNodeIdInput)) return;

        try
        {
            var response = await _client.RequestAsync<GetGraphNeighborhoodRequest, GetGraphNeighborhoodResponse>(
                MessageTypes.GetGraphNeighborhood, new GetGraphNeighborhoodRequest(GraphNodeIdInput.Trim(), 2)).ConfigureAwait(true);

            ComputeGraphLayout(GraphNodeIdInput.Trim(), response.Nodes, response.Edges);
            StatusMessage = $"Graph loaded: {response.Nodes.Count} neighbor(s), {response.Edges.Count} edge(s).";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to load graph: {ex.Message}";
        }
    }

    private void ComputeGraphLayout(string centerId, IReadOnlyList<Aegis.Core.Graph.GraphNode> nodes, IReadOnlyList<Aegis.Core.Graph.GraphEdge> edges)
    {
        const double centerX = 320, centerY = 260, radius = 200;

        var positions = new Dictionary<string, (double X, double Y)>(StringComparer.OrdinalIgnoreCase) { [centerId] = (centerX, centerY) };
        var others = nodes.Where(n => !string.Equals(n.Id, centerId, StringComparison.OrdinalIgnoreCase)).ToList();
        var angleStep = others.Count == 0 ? 0 : 2 * Math.PI / others.Count;

        for (var i = 0; i < others.Count; i++)
        {
            var angle = i * angleStep;
            positions[others[i].Id] = (centerX + radius * Math.Cos(angle), centerY + radius * Math.Sin(angle));
        }

        PositionedGraphNodes.Clear();
        PositionedGraphNodes.Add(new GraphNodeViewModel { Id = centerId, TypeLabel = "Search target", X = centerX - 8, Y = centerY - 8, Fill = "#4FD1C5" });
        foreach (var n in others)
        {
            var (x, y) = positions[n.Id];
            PositionedGraphNodes.Add(new GraphNodeViewModel { Id = n.Id, TypeLabel = n.Type.ToString(), X = x - 8, Y = y - 8, Fill = ColorForNodeType(n.Type) });
        }

        PositionedGraphEdges.Clear();
        foreach (var e in edges)
        {
            if (positions.TryGetValue(e.FromId, out var from) && positions.TryGetValue(e.ToId, out var to))
            {
                // Offset to the visual center of each 16x16 node ellipse, not its top-left corner.
                PositionedGraphEdges.Add(new GraphEdgeViewModel { X1 = from.X + 8, Y1 = from.Y + 8, X2 = to.X + 8, Y2 = to.Y + 8, Label = e.Type.ToString() });
            }
        }
    }

    private static string ColorForNodeType(Aegis.Core.Graph.GraphNodeType type) => type switch
    {
        Aegis.Core.Graph.GraphNodeType.Host => "#4FD1C5",
        Aegis.Core.Graph.GraphNodeType.Identity => "#F6AD55",
        Aegis.Core.Graph.GraphNodeType.Process => "#63B3ED",
        Aegis.Core.Graph.GraphNodeType.DecoyResource => "#FC8181",
        Aegis.Core.Graph.GraphNodeType.Destination => "#B794F4",
        _ => "#9A9CAD",
    };

    public void Dispose()
    {
        _refreshTimer.Stop();
        // Window.Closed is a synchronous event, so a blocking wait here is the lesser evil
        // versus leaking the pipe handle - this runs once at shutdown, never on a hot path.
        _client?.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }
}
