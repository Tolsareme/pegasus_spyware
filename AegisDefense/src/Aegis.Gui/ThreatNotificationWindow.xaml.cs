using System.Windows;
using Aegis.Core.Events;
using Aegis.Gui.ViewModels;

namespace Aegis.Gui;

/// <summary>
/// Non-modal "new alert" toast shown when the active policy has
/// <see cref="Aegis.Core.Policy.NotificationMode.InteractiveAction"/> selected. Backed directly
/// by the <see cref="Alert"/> instance for its bindings; the three buttons call straight through
/// to the same <see cref="MainViewModel"/> commands the Alerts tab uses, so a decision made here
/// and a decision made from the tab go through one code path.
/// </summary>
public partial class ThreatNotificationWindow : Window
{
    private readonly MainViewModel _viewModel;
    private readonly Alert _alert;

    public ThreatNotificationWindow(MainViewModel viewModel, Alert alert)
    {
        InitializeComponent();
        _viewModel = viewModel;
        _alert = alert;
        DataContext = alert;
    }

    private void OnRemoveClick(object sender, RoutedEventArgs e)
    {
        _viewModel.RemoveThreatCommand.Execute(_alert);
        Close();
    }

    private void OnQuarantineClick(object sender, RoutedEventArgs e)
    {
        _viewModel.QuarantineThreatCommand.Execute(_alert);
        Close();
    }

    private void OnIgnoreClick(object sender, RoutedEventArgs e)
    {
        _viewModel.IgnoreThreatCommand.Execute(_alert);
        Close();
    }
}
