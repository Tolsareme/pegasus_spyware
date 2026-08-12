namespace Aegis.ResponseActions;

/// <summary>Sidecar written next to a quarantined file so <c>RestoreQuarantinedFileAsync</c> knows where it came from.</summary>
internal sealed record QuarantineMetadata(string OriginalPath, DateTimeOffset QuarantinedAt);

/// <summary>Backs up a service's pre-disable start type (read from the registry, since
/// <see cref="System.ServiceProcess.ServiceController"/> doesn't expose it) so it can be restored later.</summary>
internal sealed record ServiceStartTypeBackup(string ServiceName, int StartType);

/// <summary>Backs up a registry persistence value before deleting it. <c>Value</c> is the
/// string form of whatever was stored - this round-trips cleanly for the dominant case
/// (REG_SZ/REG_EXPAND_SZ command lines, which is what every Run/RunOnce key entry actually is)
/// but is a best-effort conversion for other value kinds (Binary/MultiString), not a byte-exact
/// guarantee - see <c>WindowsResponseExecutor.RestoreRegistryValue</c>.</summary>
internal sealed record RegistryValueBackup(string Identifier, string Value, string ValueKind);
