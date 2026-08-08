namespace Aegis.Ipc;

public static class PipeConstants
{
    /// <summary>
    /// Local-machine named pipe used between Aegis.Service and Aegis.Gui. Access is
    /// restricted server-side to Administrators + LocalSystem (see AegisPipeServer) so a
    /// non-elevated local user cannot query alerts or, worse, submit policy changes.
    /// </summary>
    public const string PipeName = "AegisDefense.Control.v1";

    public static readonly TimeSpan DefaultRequestTimeout = TimeSpan.FromSeconds(15);
    public static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(5);
}
