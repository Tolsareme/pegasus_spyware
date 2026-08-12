using System.Collections.Generic;
using System.Windows;
using System.Windows.Forms;
using Aegis.Gui.Services;
using Aegis.Gui.ViewModels;

namespace Aegis.Gui;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel = new();
    private readonly TrayIconService _tray = new();

    /// <summary>Currently-open interactive toast popups, oldest first, so a new one can stack
    /// above the others instead of overlapping them.</summary>
    private readonly List<ThreatNotificationWindow> _openNotifications = new();

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _viewModel;

        _viewModel.NewCriticalAlert += OnNewCriticalAlert;
        _viewModel.NewAlertForInteractiveNotification += OnNewAlertForInteractiveNotification;
        _viewModel.ResponseActionTaken += OnResponseActionTaken;
        _tray.RestoreRequested += () => Dispatcher.Invoke(RestoreFromTray);
        _tray.ExitRequested += () => Dispatcher.Invoke(Close);

        Loaded += async (_, _) => await _viewModel.InitializeAsync().ConfigureAwait(true);
        Closed += (_, _) =>
        {
            _viewModel.NewCriticalAlert -= OnNewCriticalAlert;
            _viewModel.NewAlertForInteractiveNotification -= OnNewAlertForInteractiveNotification;
            _viewModel.ResponseActionTaken -= OnResponseActionTaken;
            _viewModel.Dispose();
            _tray.Dispose();
        };
    }

    private void OnNewCriticalAlert(Aegis.Core.Events.Alert alert)
    {
        // NewCriticalAlert fires from the refresh timer's continuation, already marshaled
        // back to the UI thread via MainViewModel's ConfigureAwait(true) chain, so no
        // additional Dispatcher hop is needed here.
        _tray.ShowCriticalAlertBalloon("Aegis Defense - Critical Alert", $"{alert.HostId}: {alert.Title}");
    }

    private void OnResponseActionTaken(string description)
    {
        // Same UI-thread guarantee as OnNewCriticalAlert above - fired from MainViewModel's
        // refresh continuation.
        _tray.ShowBalloon("Aegis Defense - Response Action", description, ToolTipIcon.Info);
    }

    private void OnNewAlertForInteractiveNotification(Aegis.Core.Events.Alert alert)
    {
        var popup = new ThreatNotificationWindow(_viewModel, alert);
        PositionPopup(popup);
        popup.Closed += (_, _) => _openNotifications.Remove(popup);
        _openNotifications.Add(popup);
        popup.Show();
    }

    /// <summary>Stacks toasts bottom-up from the work area's bottom-right corner, like a
    /// conventional notification-center tray, so several near-simultaneous alerts don't
    /// overlap each other.</summary>
    private void PositionPopup(ThreatNotificationWindow popup)
    {
        var workArea = SystemParameters.WorkArea;
        const double margin = 12;
        var top = workArea.Bottom - margin - popup.Height;
        foreach (var existing in _openNotifications)
        {
            top -= existing.Height + margin;
        }

        popup.Left = workArea.Right - margin - popup.Width;
        popup.Top = top;
    }

    private void RestoreFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }
}
