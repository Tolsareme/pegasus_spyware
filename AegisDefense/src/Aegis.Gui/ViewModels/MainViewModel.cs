using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Threading;
using Aegis.Core.Deception;
using Aegis.Core.Events;
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

            var alerts = await _client.RequestAsync<GetAlertsRequest, GetAlertsResponse>(MessageTypes.GetAlerts, new GetAlertsRequest(null, null, 200)).ConfigureAwait(true);
            ReplaceAll(Alerts, alerts.Alerts);

            var events = await _client.RequestAsync<GetEventsRequest, GetEventsResponse>(MessageTypes.GetEvents, new GetEventsRequest(null, null, 300)).ConfigureAwait(true);
            ReplaceAll(Events, events.Events);

            var approvals = await _client.RequestAsync<GetPendingApprovalsRequest, GetPendingApprovalsResponse>(MessageTypes.GetPendingApprovals, new GetPendingApprovalsRequest()).ConfigureAwait(true);
            ReplaceAll(PendingApprovals, approvals.Approvals);

            var vulns = await _client.RequestAsync<GetVulnerabilitiesRequest, GetVulnerabilitiesResponse>(MessageTypes.GetVulnerabilities, new GetVulnerabilitiesRequest(null)).ConfigureAwait(true);
            ReplaceAll(Vulnerabilities, vulns.Vulnerabilities);

            var decoys = await _client.RequestAsync<ListDecoysRequest, ListDecoysResponse>(MessageTypes.ListDecoys, new ListDecoysRequest()).ConfigureAwait(true);
            ReplaceAll(Decoys, decoys.Decoys);

            var policy = await _client.RequestAsync<GetPolicyRequest, GetPolicyResponse>(MessageTypes.GetPolicy, new GetPolicyRequest()).ConfigureAwait(true);
            ActivePolicy = policy.Policy;

            var whoAmI = await _client.RequestAsync<WhoAmIRequest, WhoAmIResponse>(MessageTypes.WhoAmI, new WhoAmIRequest()).ConfigureAwait(true);
            Role = whoAmI.Role;

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

    public void Dispose()
    {
        _refreshTimer.Stop();
        // Window.Closed is a synchronous event, so a blocking wait here is the lesser evil
        // versus leaking the pipe handle - this runs once at shutdown, never on a hot path.
        _client?.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }
}
