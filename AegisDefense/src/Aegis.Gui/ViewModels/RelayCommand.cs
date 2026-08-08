using System.Windows.Input;

namespace Aegis.Gui.ViewModels;

/// <summary>Minimal ICommand implementation - avoids pulling in a full MVVM framework for a control panel this size.</summary>
public sealed class RelayCommand : ICommand
{
    private readonly Func<object?, Task> _executeAsync;
    private readonly Func<object?, bool>? _canExecute;
    private bool _isRunning;

    public RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
        : this(o => { execute(o); return Task.CompletedTask; }, canExecute)
    {
    }

    public RelayCommand(Func<object?, Task> executeAsync, Func<object?, bool>? canExecute = null)
    {
        _executeAsync = executeAsync;
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }

    public bool CanExecute(object? parameter) => !_isRunning && (_canExecute?.Invoke(parameter) ?? true);

    public async void Execute(object? parameter)
    {
        _isRunning = true;
        CommandManager.InvalidateRequerySuggested();
        try
        {
            await _executeAsync(parameter).ConfigureAwait(true);
        }
        finally
        {
            _isRunning = false;
            CommandManager.InvalidateRequerySuggested();
        }
    }
}
