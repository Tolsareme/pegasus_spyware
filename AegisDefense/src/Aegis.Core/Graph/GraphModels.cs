namespace Aegis.Core.Graph;

public enum GraphNodeType
{
    Host,
    Identity,
    Process,
    File,
    Service,
    ScheduledTask,
    Credential,
    Destination,
    SecurityEvent,
    DecoyResource,
}

public enum GraphEdgeType
{
    LogsOnTo,
    Spawns,
    Writes,
    Deletes,
    ConnectsTo,
    Creates,
    Accesses,
    Modifies,
}

/// <summary>A node in the attack-state graph (doc §9): hosts, identities, processes, files, services, credentials/tokens, destinations, security events.</summary>
public sealed record GraphNode
{
    public required string Id { get; init; }
    public required GraphNodeType Type { get; init; }
    public DateTimeOffset FirstSeen { get; init; }
    public DateTimeOffset LastSeen { get; init; }
}

/// <summary>A relationship/action edge, e.g. Identity --logs_on_to--> Host, Process --connects_to--> Destination.</summary>
public sealed record GraphEdge
{
    public required string FromId { get; init; }
    public required string ToId { get; init; }
    public required GraphEdgeType Type { get; init; }
    public required DateTimeOffset Timestamp { get; init; }
    public required Guid SourceEventId { get; init; }
}
