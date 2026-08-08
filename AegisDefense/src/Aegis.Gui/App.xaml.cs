namespace Aegis.Gui;

// Fully qualified rather than `using System.Windows;` - enabling UseWindowsForms (for the
// v2 tray icon) makes System.Windows.Forms.Application an implicit global using too, and
// both namespaces define an `Application` type.
public partial class App : System.Windows.Application
{
}
