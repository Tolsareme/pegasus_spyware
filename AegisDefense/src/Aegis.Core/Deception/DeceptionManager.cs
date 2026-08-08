using Aegis.Core.Events;

namespace Aegis.Core.Deception;

public enum DecoyType
{
    File,
    Directory,
    ServiceIdentity,
    HoneyCredential,
    Share,
    Api,
}

/// <summary>
/// One deployed decoy (doc §15). <see cref="GrantsRealPrivilege"/> is deliberately not
/// settable - it is always false - so it is structurally impossible to register a "decoy"
/// that actually carries production privilege ("decoys must never contain real secrets").
/// </summary>
public sealed class DecoyResourceDefinition
{
    public required string Id { get; init; }
    public required DecoyType Type { get; init; }
    public required string Location { get; init; } // path, share UNC, API route, or identity name
    public required string Description { get; init; }
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>Restrict this decoy to a single host, or null to deploy the definition everywhere.</summary>
    public string? HostIdScope { get; init; }

    public bool GrantsRealPrivilege => false;
}

/// <summary>
/// Central registry mapping decoy locations to definitions, and reclassifying raw events
/// that touch a decoy into high-confidence <see cref="ActionType.CanaryAccess"/> events
/// before they reach the rule engine. Keeping this logic here (rather than in every
/// collector) means the sensor stays "dumb" and canary classification is unit-testable
/// in one place.
/// </summary>
public sealed class DeceptionManager
{
    private readonly List<DecoyResourceDefinition> _decoys = new();

    public IReadOnlyList<DecoyResourceDefinition> Decoys => _decoys;

    public void RegisterDecoy(DecoyResourceDefinition decoy)
    {
        if (_decoys.Any(d => d.Id == decoy.Id))
            throw new InvalidOperationException($"Decoy '{decoy.Id}' already registered.");
        _decoys.Add(decoy);
    }

    public bool RemoveDecoy(string id) => _decoys.RemoveAll(d => d.Id == id) > 0;

    public DecoyResourceDefinition? Match(string hostId, string? objectIdOrPath)
    {
        if (string.IsNullOrEmpty(objectIdOrPath)) return null;
        return _decoys.FirstOrDefault(d =>
            (d.HostIdScope is null || string.Equals(d.HostIdScope, hostId, StringComparison.OrdinalIgnoreCase)) &&
            string.Equals(d.Location, objectIdOrPath, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Returns a reclassified copy of <paramref name="evt"/> as a canary hit if it touches a
    /// registered decoy, otherwise null. Any action type (file access, auth attempt, API
    /// call, share access) can trigger this - legitimate software has no reason to touch a
    /// decoy at all (doc §15).
    /// </summary>
    public NormalizedEvent? TryClassifyCanaryAccess(NormalizedEvent evt)
    {
        var candidate = evt.ObjectId ?? evt.ImagePath;
        var decoy = Match(evt.HostId, candidate);
        if (decoy is null) return null;

        return evt with
        {
            ActionType = ActionType.CanaryAccess,
            ObjectType = ObjectType.DecoyResource,
            ObjectId = decoy.Id,
            Confidence = 1.0,
        };
    }
}
