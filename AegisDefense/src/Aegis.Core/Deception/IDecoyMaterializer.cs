using Aegis.Core.Response;

namespace Aegis.Core.Deception;

/// <summary>
/// Creates/removes the real on-host artifact a <see cref="DecoyResourceDefinition"/> describes,
/// so a collector actually has something to observe access to. Registering the definition alone
/// (<see cref="DeceptionManager.RegisterDecoy"/>) only teaches the engine to *reclassify* access
/// to that location as a canary hit - it does not by itself make the location exist. Implemented
/// by <c>Aegis.ResponseActions.WindowsDecoyMaterializer</c> (v2); defaults to
/// <see cref="NullDecoyMaterializer"/> so decoys registered without a materializer configured
/// still behave exactly as before (the operator creates the artifact by hand) - materialization
/// is an added convenience, never a hard requirement for canary matching to work.
/// </summary>
public interface IDecoyMaterializer
{
    Task<ResponseActionResult> MaterializeAsync(DecoyResourceDefinition decoy, CancellationToken ct = default);

    Task<ResponseActionResult> RemoveAsync(DecoyResourceDefinition decoy, CancellationToken ct = default);
}

/// <summary>No-op default: the decoy definition is still registered and matched normally - this
/// just means nobody automatically created the underlying file/directory/share, so it must be
/// created manually (or a real <see cref="IDecoyMaterializer"/> must be configured) for a
/// collector to observe access to it.</summary>
public sealed class NullDecoyMaterializer : IDecoyMaterializer
{
    public Task<ResponseActionResult> MaterializeAsync(DecoyResourceDefinition decoy, CancellationToken ct = default) =>
        Task.FromResult(new ResponseActionResult
        {
            Success = false,
            Detail = "No decoy materializer is configured on this host - the decoy definition is registered and will be matched, but its physical artifact was not created automatically. Create it manually at the registered location, or configure a real IDecoyMaterializer (see Aegis.ResponseActions.WindowsDecoyMaterializer).",
            Reversible = true,
        });

    public Task<ResponseActionResult> RemoveAsync(DecoyResourceDefinition decoy, CancellationToken ct = default) =>
        Task.FromResult(new ResponseActionResult { Success = true, Detail = "No decoy materializer configured - nothing to remove.", Reversible = true });
}
