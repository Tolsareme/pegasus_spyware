namespace Aegis.Core.Features;

/// <summary>
/// Point-in-time behavioral features for one host, recomputed as each new event arrives.
/// Mirrors the bullet list in doc §7 "Feature Engineering". Values are intentionally
/// simple/explainable (counts, rates, deltas) rather than opaque embeddings, so the
/// rule engine and the evidence trail shown in the GUI stay human-auditable.
/// </summary>
public sealed record FeatureSnapshot
{
    public required string HostId { get; init; }

    public required DateTimeOffset AsOf { get; init; }

    /// <summary>0 (very common) .. 1 (never seen before on this host/role) parent-&gt;child process rarity.</summary>
    public double ProcessRarity { get; init; }

    /// <summary>0..1 heuristic for command/script obfuscation (encoded blocks, string-building, download cradles, excessive length).</summary>
    public double CommandComplexity { get; init; }

    /// <summary>Authentication failures inside the rolling window.</summary>
    public int AuthFailureCount { get; init; }

    /// <summary>Failures immediately followed by a success - classic spray/guess signature.</summary>
    public int AuthFailureThenSuccessCount { get; init; }

    /// <summary>Logons using a type unusual for this host/identity pair (e.g. interactive on a headless server).</summary>
    public int UnusualLogonTypeCount { get; init; }

    /// <summary>Distinct remote hosts contacted per minute over the window.</summary>
    public double RemoteContactRate { get; init; }

    /// <summary>Remote hosts contacted in this window that had never been contacted before.</summary>
    public int NewDestinationCount { get; init; }

    /// <summary>Privilege-assignment / security-control-change events in the window.</summary>
    public int PrivilegeChangeCount { get; init; }

    /// <summary>Seconds between a suspicious execution and a persistence artifact (service/task/run-key) being created; null if none observed.</summary>
    public double? PersistenceAfterExecutionSeconds { get; init; }

    /// <summary>Seconds between credential-sensitive access and a subsequent remote authentication; null if none observed.</summary>
    public double? CredentialToRemoteAuthSeconds { get; init; }

    /// <summary>How many times a failed action was immediately followed by a *different* technique (adaptation signature).</summary>
    public int TechniqueSwitchAfterFailureCount { get; init; }

    /// <summary>Seconds between a discovery/recon result and the next action that appears to use it; null if none observed.</summary>
    public double? ReconToActionSeconds { get; init; }

    /// <summary>Number of distinct hosts in the enterprise showing a similar action sequence within the window (requires cross-host correlation feed; 0 if unavailable).</summary>
    public int CrossHostSimilarHostCount { get; init; }

    /// <summary>Raw event count backing this snapshot - useful for confidence weighting on sparse hosts.</summary>
    public int WindowEventCount { get; init; }

    /// <summary>File create/write/delete/rename events observed in the last 60 seconds - mass-modification / ransomware-style indicator (doc §5 "Files" telemetry).</summary>
    public int FileWriteBurstCount { get; init; }

    /// <summary>True if any recent file write was tagged high-entropy by the sensor (content looks encrypted/packed).</summary>
    public bool HighEntropyWriteObserved { get; init; }
}
