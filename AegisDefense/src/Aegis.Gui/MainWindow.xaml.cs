using System.Windows;
using Aegis.Gui.ViewModels;

namespace Aegis.Gui;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel = new();

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _viewModel;
        Loaded += async (_, _) => await _viewModel.InitializeAsync().ConfigureAwait(true);
        Closed += (_, _) => _viewModel.Dispose();
    }
}
