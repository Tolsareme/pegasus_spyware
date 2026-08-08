using System.Windows;
using Aegis.Gui.Services;
using Aegis.Gui.ViewModels;

namespace Aegis.Gui;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel = new();
    private readonly TrayIconService _tray = new();

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _viewModel;

        _viewModel.NewCriticalAlert += OnNewCriticalAlert;
        _tray.RestoreRequested += () => Dispatcher.Invoke(RestoreFromTray);
        _tray.ExitRequested += () => Dispatcher.Invoke(Close);

        Loaded += async (_, _) => await _viewModel.InitializeAsync().ConfigureAwait(true);
        Closed += (_, _) =>
        {
            _viewModel.NewCriticalAlert -= OnNewCriticalAlert;
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

    private void RestoreFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }
}
