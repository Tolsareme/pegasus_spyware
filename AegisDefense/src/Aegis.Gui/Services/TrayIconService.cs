using System.Windows.Forms;

namespace Aegis.Gui.Services;

/// <summary>
/// A system-tray presence for the console via <see cref="NotifyIcon"/> (WinForms, referenced
/// directly - this is the standard, supported way to get a tray icon from WPF; there is no
/// WPF-native equivalent). Uses a built-in <see cref="System.Drawing.SystemIcons"/> icon so
/// no custom .ico asset is needed. Shows a balloon tip for newly discovered critical alerts
/// and offers a right-click menu to restore/exit, matching the notification behavior the v2
/// roadmap asked for ("push notifications / tray icon... critical alerts should be able to
/// alert the operator even when the console isn't focused").
/// </summary>
public sealed class TrayIconService : IDisposable
{
    private readonly NotifyIcon _icon;

    public event Action? RestoreRequested;
    public event Action? ExitRequested;

    public TrayIconService()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Show Console", null, (_, _) => RestoreRequested?.Invoke());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) => ExitRequested?.Invoke());

        _icon = new NotifyIcon
        {
            Icon = System.Drawing.SystemIcons.Shield,
            Text = "Aegis Defense Console",
            Visible = true,
            ContextMenuStrip = menu,
        };
        _icon.DoubleClick += (_, _) => RestoreRequested?.Invoke();
    }

    public void ShowCriticalAlertBalloon(string title, string message) =>
        ShowBalloon(title, message, ToolTipIcon.Warning);

    /// <summary>General-purpose balloon, e.g. for "response action taken" info notices that
    /// aren't severe enough to warrant the Warning icon a new critical alert gets.</summary>
    public void ShowBalloon(string title, string message, ToolTipIcon icon = ToolTipIcon.Info)
    {
        _icon.BalloonTipIcon = icon;
        _icon.BalloonTipTitle = title;
        _icon.BalloonTipText = message;
        _icon.ShowBalloonTip(10_000);
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
    }
}
