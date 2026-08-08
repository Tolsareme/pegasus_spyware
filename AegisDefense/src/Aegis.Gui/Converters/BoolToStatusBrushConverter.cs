using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace Aegis.Gui.Converters;

/// <summary>true -> accent (green/teal) brush, false -> critical (red) brush. Used for the connection dot and engine-enabled dots.</summary>
public sealed class BoolToStatusBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush OnBrush = new(Color.FromRgb(0x4F, 0xD1, 0xC5));
    private static readonly SolidColorBrush OffBrush = new(Color.FromRgb(0xFC, 0x81, 0x81));

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is true ? OnBrush : OffBrush;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
