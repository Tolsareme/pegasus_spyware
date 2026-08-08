namespace Aegis.Core.Events;

/// <summary>
/// Common event schema every Windows telemetry provider (ETW, Security log, Sysmon-style
/// process/file/network, WMI, PowerShell/AMSI, services/tasks, registry, AD) is normalized
/// into, so correlation logic never depends on a specific provider. Mirrors doc §6.
/// </summary>
public sealed record NormalizedEvent
{
    /// <summary>Stable identifier assigned by the sensor at ingestion time.</summary>
    public required Guid EventId { get; init; }

    public required DateTimeOffset Timestamp { get; init; }

    public required string HostId { get; init; }

    public string? UserId { get; init; }

    public int? ProcessId { get; init; }

    public int? ParentProcessId { get; init; }

    public string? ProcessHash { get; init; }

    public string? Signer { get; init; }

    /// <summary>Full image path of the process performing the action, when applicable.</summary>
    public string? ImagePath { get; init; }

    /// <summary>Full image path of the parent process, when applicable.</summary>
    public string? ParentImagePath { get; init; }

    /// <summary>Host role classification ("Workstation", "DomainController", "SqlServer", ...) used to select the right behavioral baseline.</summary>
    public string? HostRole { get; init; }

    /// <summary>Windows logon type (2=interactive, 3=network, 10=RDP, ...) when the event is authentication-related.</summary>
    public int? LogonType { get; init; }

    public required ActionType ActionType { get; init; }

    public ObjectType ObjectType { get; init; } = ObjectType.Unknown;

    public string? ObjectId { get; init; }

    public string? SourceIp { get; init; }

    public string? DestinationIp { get; init; }

    public int? DestinationPort { get; init; }

    public string? PrivilegeContext { get; init; }

    public ActionResult Result { get; init; } = ActionResult.Unknown;

    /// <summary>0.0-1.0 confidence the sensor assigns to this observation (some providers are noisier than others).</summary>
    public double Confidence { get; init; } = 1.0;

    /// <summary>Opaque pointer back to the original provider record (e.g. an EVTX record id or ETW event) for forensic review.</summary>
    public string? RawEventReference { get; init; }

    /// <summary>Free-form command line / script content, kept separate so it can be redacted or truncated independently.</summary>
    public string? CommandLine { get; init; }

    /// <summary>Provider-specific extras that do not warrant a first-class column (kept small; not a dumping ground).</summary>
    public IReadOnlyDictionary<string, string>? Tags { get; init; }
}
