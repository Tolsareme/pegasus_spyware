using Aegis.Core.Events;

namespace Aegis.Core.Features;

/// <summary>
/// Rolling per-host behavioral state. One instance per host, fed sequentially with
/// <see cref="NormalizedEvent"/>s in timestamp order; each call to <see cref="Ingest"/>
/// returns a fresh <see cref="FeatureSnapshot"/> the rule/scoring engines consume
/// immediately (streaming, not batch). Not thread-safe by design - callers own one
/// profile per host and serialize access through the event pipeline.
/// </summary>
public sealed class HostBehaviorProfile
{
    private readonly string _hostId;
    private readonly IProcessBaseline _baseline;
    private readonly TimeSpan _window;

    private readonly LinkedList<NormalizedEvent> _recent = new();
    private readonly HashSet<string> _destinationsEverSeen = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, HashSet<int>> _logonTypesByIdentity = new(StringComparer.OrdinalIgnoreCase);

    private (ActionType Type, DateTimeOffset At)? _lastFailure;
    private DateTimeOffset? _lastSuspiciousExecutionAt;
    private DateTimeOffset? _lastCredentialAccessAt;
    private DateTimeOffset? _lastDiscoveryAt;

    private readonly LinkedList<DateTimeOffset> _recentFileWrites = new();

    private int _techniqueSwitchAfterFailureCount;
    private DateTimeOffset? _lastHighEntropyWriteAt;

    public HostBehaviorProfile(string hostId, IProcessBaseline baseline, TimeSpan? window = null)
    {
        _hostId = hostId;
        _baseline = baseline;
        _window = window ?? TimeSpan.FromMinutes(30);
    }

    public FeatureSnapshot Ingest(NormalizedEvent evt)
    {
        if (!string.Equals(evt.HostId, _hostId, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException($"Event for host '{evt.HostId}' fed into profile for '{_hostId}'.");

        _recent.AddLast(evt);
        Trim(evt.Timestamp);

        var hostRole = evt.HostRole ?? "Unknown";
        var rarity = 0.0;
        var complexity = 0.0;

        if (evt.ActionType is ActionType.ProcessCreate)
        {
            var child = evt.ImagePath ?? "unknown.exe";
            rarity = _baseline.GetLineageRarity(hostRole, evt.ParentImagePath, child);
            _baseline.Observe(hostRole, evt.ParentImagePath, child);
        }

        if (evt.ActionType is ActionType.ProcessCreate or ActionType.ScriptExecution)
        {
            complexity = CommandComplexityHeuristic.Score(evt.CommandLine);
        }

        UpdateAuthTracking(evt);
        UpdateTechniqueSwitch(evt);
        var persistenceAfterExecutionSeconds = UpdatePersistenceTiming(evt, rarity, complexity);
        var credentialToRemoteAuthSeconds = UpdateCredentialTiming(evt);
        var reconToActionSeconds = UpdateReconTiming(evt);
        UpdateFileWriteBurst(evt);

        return BuildSnapshot(evt.Timestamp, rarity, complexity, persistenceAfterExecutionSeconds, credentialToRemoteAuthSeconds, reconToActionSeconds);
    }

    private void Trim(DateTimeOffset now)
    {
        var cutoff = now - _window;
        while (_recent.First is { } node && node.Value.Timestamp < cutoff)
        {
            _recent.RemoveFirst();
        }
    }

    private void UpdateAuthTracking(NormalizedEvent evt)
    {
        if (evt.ActionType is not (ActionType.AuthenticationSuccess or ActionType.AuthenticationFailure)) return;
        if (evt.UserId is null) return;

        if (!_logonTypesByIdentity.TryGetValue(evt.UserId, out var seen))
        {
            seen = new HashSet<int>();
            _logonTypesByIdentity[evt.UserId] = seen;
        }
        if (evt.LogonType is { } lt)
        {
            seen.Add(lt);
        }
    }

    private void UpdateTechniqueSwitch(NormalizedEvent evt)
    {
        if (EventSemantics.IsFailureAction(evt))
        {
            _lastFailure = (evt.ActionType, evt.Timestamp);
            return;
        }

        if (_lastFailure is { } failure &&
            failure.Type != evt.ActionType &&
            evt.Timestamp - failure.At <= TimeSpan.FromMinutes(5))
        {
            _techniqueSwitchAfterFailureCount++;
            _lastFailure = null;
        }
    }

    /// <summary>
    /// Returns the "shortly after" delta in seconds only for the specific event that actually
    /// completes the suspicious-execution -&gt; persistence pair - never a value that lingers
    /// into unrelated later events. Confirmed as a real bug during live Windows testing: an
    /// earlier version stored this as a sticky field that, once set, was included in every
    /// subsequent <see cref="FeatureSnapshot"/> regardless of the current event's type -
    /// producing a duplicate "Persistence created shortly after suspicious execution" alert
    /// for literally every following event (routine Windows service/task churn included) for
    /// the rest of the host profile's lifetime. The anchor timestamp itself
    /// (<see cref="_lastSuspiciousExecutionAt"/>) still persists across calls, by design -
    /// several distinct persistence artifacts within the window after one suspicious execution
    /// should each still be reported once - only the *output* is now scoped to the one event
    /// that qualifies.
    /// </summary>
    private double? UpdatePersistenceTiming(NormalizedEvent evt, double rarity, double complexity)
    {
        if (EventSemantics.IsSuspiciousExecution(evt.ActionType, rarity, complexity))
        {
            _lastSuspiciousExecutionAt = evt.Timestamp;
            return null;
        }

        if (EventSemantics.IsPersistenceArtifact(evt.ActionType) && _lastSuspiciousExecutionAt is { } execAt)
        {
            var delta = (evt.Timestamp - execAt).TotalSeconds;
            if (delta is >= 0 and <= 900) // within 15 minutes counts as "shortly after" per doc §7
            {
                return delta;
            }
        }

        return null;
    }

    /// <summary>See <see cref="UpdatePersistenceTiming"/> for why this returns a per-event value instead of setting a sticky field.</summary>
    private double? UpdateCredentialTiming(NormalizedEvent evt)
    {
        if (EventSemantics.IsCredentialSensitive(evt.ActionType))
        {
            _lastCredentialAccessAt = evt.Timestamp;
            return null;
        }

        if (EventSemantics.IsRemoteAuthentication(evt.ActionType) && _lastCredentialAccessAt is { } credAt)
        {
            var delta = (evt.Timestamp - credAt).TotalSeconds;
            if (delta is >= 0 and <= 1800)
            {
                return delta;
            }
        }

        return null;
    }

    /// <summary>
    /// See <see cref="UpdatePersistenceTiming"/> for why this returns a per-event value instead
    /// of setting a sticky field. This one needs an extra step beyond that fix: unlike
    /// persistence/credential timing (each scoped to a specific, comparatively rare target
    /// ActionType), "action after recon" deliberately matches *any* subsequent event - so
    /// without also consuming <see cref="_lastDiscoveryAt"/> once it produces a match, this
    /// would still fire on every single following event for the rest of the 10-minute window
    /// (a smaller version of the same duplicate-alert flood the sticky-field bug caused). The
    /// anchor is cleared after reporting the first action that follows a discovery-like event,
    /// matching the rule's actual description ("Action taken only Ns after a discovery/
    /// reconnaissance result") - singular, not "everything for the next 10 minutes."
    /// </summary>
    private double? UpdateReconTiming(NormalizedEvent evt)
    {
        if (EventSemantics.IsDiscoveryLike(evt.ActionType, evt.ObjectType))
        {
            _lastDiscoveryAt = evt.Timestamp;
            return null;
        }

        if (_lastDiscoveryAt is { } reconAt && evt.ActionType is not ActionType.AuthenticationFailure)
        {
            var delta = (evt.Timestamp - reconAt).TotalSeconds;
            if (delta is >= 0 and <= 600)
            {
                _lastDiscoveryAt = null;
                return delta;
            }
        }

        return null;
    }

    private static readonly TimeSpan FileBurstWindow = TimeSpan.FromSeconds(60);

    /// <summary>Tracks file create/write/delete/rename events in a 60s sliding window and records whether the write looked high-entropy.</summary>
    private void UpdateFileWriteBurst(NormalizedEvent evt)
    {
        var isFileMutation = evt.ActionType is ActionType.FileCreate or ActionType.FileWrite or ActionType.FileDelete or ActionType.FileRename;
        if (isFileMutation)
        {
            _recentFileWrites.AddLast(evt.Timestamp);
        }

        var cutoff = evt.Timestamp - FileBurstWindow;
        while (_recentFileWrites.First is { } node && node.Value < cutoff)
        {
            _recentFileWrites.RemoveFirst();
        }

        var highEntropy = isFileMutation && evt.Tags is not null &&
               evt.Tags.TryGetValue("Entropy", out var entropyStr) &&
               double.TryParse(entropyStr, out var entropy) && entropy >= 7.5; // Shannon entropy near 8 ~= encrypted/compressed content
        if (highEntropy)
        {
            _lastHighEntropyWriteAt = evt.Timestamp;
        }
    }

    private FeatureSnapshot BuildSnapshot(DateTimeOffset asOf, double rarity, double complexity,
        double? persistenceAfterExecutionSeconds, double? credentialToRemoteAuthSeconds, double? reconToActionSeconds)
    {
        var windowStart = asOf - _window;
        var windowEvents = _recent; // already trimmed

        var authFailures = 0;
        var authFailThenSuccess = 0;
        var unusualLogonTypes = 0;
        var privilegeChanges = 0;
        var newDestinations = 0;
        var destinationsThisWindow = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        NormalizedEvent? lastAuthFailure = null;

        foreach (var e in windowEvents)
        {
            switch (e.ActionType)
            {
                case ActionType.AuthenticationFailure:
                    authFailures++;
                    lastAuthFailure = e;
                    break;
                case ActionType.AuthenticationSuccess:
                    if (lastAuthFailure is not null &&
                        string.Equals(lastAuthFailure.UserId, e.UserId, StringComparison.OrdinalIgnoreCase) &&
                        (e.Timestamp - lastAuthFailure.Timestamp) <= TimeSpan.FromMinutes(10))
                    {
                        authFailThenSuccess++;
                        lastAuthFailure = null;
                    }
                    if (e.UserId is not null && e.LogonType is { } lt2 &&
                        _logonTypesByIdentity.TryGetValue(e.UserId, out var seenTypes) &&
                        seenTypes.Count > 1 && !IsCommonLogonType(lt2))
                    {
                        unusualLogonTypes++;
                    }
                    break;
                case ActionType.PrivilegeAssigned:
                case ActionType.SecurityControlChange:
                    privilegeChanges++;
                    break;
                case ActionType.NetworkConnect when e.DestinationIp is not null:
                    destinationsThisWindow.Add(e.DestinationIp);
                    if (_destinationsEverSeen.Add(e.DestinationIp))
                    {
                        newDestinations++;
                    }
                    break;
            }
        }

        var minutes = Math.Max(1.0, (asOf - windowStart).TotalMinutes);
        var contactRate = destinationsThisWindow.Count / minutes;

        return new FeatureSnapshot
        {
            HostId = _hostId,
            AsOf = asOf,
            ProcessRarity = rarity,
            CommandComplexity = complexity,
            AuthFailureCount = authFailures,
            AuthFailureThenSuccessCount = authFailThenSuccess,
            UnusualLogonTypeCount = unusualLogonTypes,
            RemoteContactRate = contactRate,
            NewDestinationCount = newDestinations,
            PrivilegeChangeCount = privilegeChanges,
            PersistenceAfterExecutionSeconds = persistenceAfterExecutionSeconds,
            CredentialToRemoteAuthSeconds = credentialToRemoteAuthSeconds,
            TechniqueSwitchAfterFailureCount = _techniqueSwitchAfterFailureCount,
            ReconToActionSeconds = reconToActionSeconds,
            CrossHostSimilarHostCount = 0, // populated by an enterprise-level correlator (WP3+), not a single host profile
            WindowEventCount = windowEvents.Count,
            FileWriteBurstCount = _recentFileWrites.Count,
            HighEntropyWriteObserved = _lastHighEntropyWriteAt is { } t && (asOf - t) <= TimeSpan.FromMinutes(5),
        };
    }

    private static bool IsCommonLogonType(int logonType) => logonType is 2 or 3 or 4 or 5 or 7 or 11;
}
