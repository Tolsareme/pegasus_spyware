using Microsoft.Win32;
using Aegis.Core.Diagnostics;
using Aegis.Core.Events;
using Aegis.Core.Telemetry;

namespace Aegis.Sensor.Collectors;

/// <summary>
/// Polls well-known autorun/persistence registry locations and diffs value sets - simple,
/// works identically on every supported Windows version, and covers the doc §5 "Registry"
/// row's "Run keys, services, security-sensitive configuration" without needing a kernel
/// registry-callback driver. Poll interval trades a small detection-latency cost for zero
/// extra privilege/driver requirements.
/// </summary>
public sealed class RegistryPersistenceCollector : ITelemetryCollector
{
    public string Name => "RegistryPersistence";

    private static readonly (RegistryHive Hive, string Path)[] WatchedKeys =
    {
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"),
        (RegistryHive.Users, @".DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    };

    private readonly string _hostId;
    private readonly string _hostRole;
    private readonly TimeSpan _pollInterval;
    private Timer? _timer;
    private readonly Dictionary<string, string> _knownValues = new();
    private readonly object _lock = new();

    public RegistryPersistenceCollector(string hostId, string hostRole, TimeSpan? pollInterval = null)
    {
        _hostId = hostId;
        _hostRole = hostRole;
        _pollInterval = pollInterval ?? TimeSpan.FromSeconds(30);
    }

    public void Start(Action<NormalizedEvent> onEvent, IAegisLogger logger)
    {
        // Seed the baseline on startup without emitting events for pre-existing (presumably
        // legitimate) entries - only *changes* after the sensor starts are interesting.
        SnapshotAll(logger);
        _timer = new Timer(_ => Poll(onEvent, logger), null, _pollInterval, _pollInterval);
    }

    private void SnapshotAll(IAegisLogger logger)
    {
        foreach (var (hive, path) in WatchedKeys)
        {
            foreach (var (name, value) in ReadKeyValues(hive, path, logger))
            {
                _knownValues[$"{hive}\\{path}\\{name}"] = value;
            }
        }
    }

    private void Poll(Action<NormalizedEvent> onEvent, IAegisLogger logger)
    {
        lock (_lock)
        {
            foreach (var (hive, path) in WatchedKeys)
            {
                var current = ReadKeyValues(hive, path, logger);
                foreach (var (name, value) in current)
                {
                    var fullKey = $"{hive}\\{path}\\{name}";
                    if (!_knownValues.TryGetValue(fullKey, out var previous))
                    {
                        Emit(onEvent, hive, path, name, value, isNew: true);
                    }
                    else if (previous != value)
                    {
                        Emit(onEvent, hive, path, name, value, isNew: false);
                    }
                    _knownValues[fullKey] = value;
                }
            }
        }
    }

    private void Emit(Action<NormalizedEvent> onEvent, RegistryHive hive, string path, string valueName, string value, bool isNew)
    {
        onEvent(new NormalizedEvent
        {
            EventId = Guid.NewGuid(),
            Timestamp = DateTimeOffset.UtcNow,
            HostId = _hostId,
            HostRole = _hostRole,
            ActionType = ActionType.RegistrySet,
            ObjectType = ObjectType.RegistryKey,
            ObjectId = $@"{hive}\{path}\{valueName}",
            CommandLine = value, // the run-key's target command line, reused so ObfuscationHeuristic can inspect it too
            Result = ActionResult.Success,
            Tags = new Dictionary<string, string> { ["Change"] = isNew ? "Added" : "Modified" },
            RawEventReference = $"Registry:{hive}\\{path}\\{valueName}:{DateTimeOffset.UtcNow.Ticks}",
        });
    }

    private static List<(string Name, string Value)> ReadKeyValues(RegistryHive hive, string path, IAegisLogger logger)
    {
        var results = new List<(string, string)>();
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            using var key = baseKey.OpenSubKey(path);
            if (key is null) return results;

            foreach (var valueName in key.GetValueNames())
            {
                var value = key.GetValue(valueName)?.ToString() ?? string.Empty;
                results.Add((string.IsNullOrEmpty(valueName) ? "(default)" : valueName, value));
            }
        }
        catch (Exception ex)
        {
            logger.Debug("RegistryPersistence", $"Could not read {hive}\\{path}: {ex.Message}");
        }
        return results;
    }

    public void Stop() => _timer?.Change(Timeout.Infinite, Timeout.Infinite);

    public void Dispose()
    {
        Stop();
        _timer?.Dispose();
    }
}
