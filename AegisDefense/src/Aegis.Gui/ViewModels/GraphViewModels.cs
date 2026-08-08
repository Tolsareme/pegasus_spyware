namespace Aegis.Gui.ViewModels;

/// <summary>One rendered node: absolute Canvas.Left/Top plus a display label and fill color derived from the underlying graph node's type.</summary>
public sealed class GraphNodeViewModel
{
    public required string Id { get; init; }
    public required string TypeLabel { get; init; }
    public required double X { get; init; }
    public required double Y { get; init; }
    public required string Fill { get; init; }

    /// <summary>Trimmed for on-canvas display - full id is in the tooltip.</summary>
    public string ShortLabel => Id.Length <= 22 ? Id : Id.Substring(0, 19) + "...";
}

/// <summary>One rendered edge: a straight line between two already-positioned nodes.</summary>
public sealed class GraphEdgeViewModel
{
    public required double X1 { get; init; }
    public required double Y1 { get; init; }
    public required double X2 { get; init; }
    public required double Y2 { get; init; }
    public required string Label { get; init; }
}
