using Aegis.Core.Compat;

namespace Aegis.Core.Features;

/// <summary>
/// Learned "what is normal" store for parent-&gt;child process lineage, keyed by host role
/// (e.g. "DomainController", "Workstation", "SqlServer"). WP2 in the research doc
/// ("Baseline Behavior") is expected to replace <see cref="InMemoryProcessBaseline"/>
/// with a properly trained/periodically-refreshed model; the interface is the seam.
/// </summary>
public interface IProcessBaseline
{
    /// <summary>Returns a rarity score in [0,1]; 0 = extremely common for this role, 1 = never observed.</summary>
    double GetLineageRarity(string hostRole, string? parentImage, string childImage);

    /// <summary>Records an observation so future rarity lookups reflect it (online learning).</summary>
    void Observe(string hostRole, string? parentImage, string childImage);
}

/// <summary>
/// Simple frequency-count baseline good enough for the MVP and for unit tests.
/// Thread-safe for single-process, single-service use (one lock per role bucket).
/// </summary>
public sealed class InMemoryProcessBaseline : IProcessBaseline
{
    private sealed class RoleBucket
    {
        public readonly Dictionary<string, long> Counts = new(StringComparer.OrdinalIgnoreCase);
        public long Total;
        public readonly object Lock = new();
    }

    private readonly Dictionary<string, RoleBucket> _roles = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _rolesLock = new();

    private static string Key(string? parentImage, string childImage) =>
        $"{parentImage ?? "?"}=>{childImage}";

    private RoleBucket GetBucket(string hostRole)
    {
        lock (_rolesLock)
        {
            if (!_roles.TryGetValue(hostRole, out var bucket))
            {
                bucket = new RoleBucket();
                _roles[hostRole] = bucket;
            }
            return bucket;
        }
    }

    public double GetLineageRarity(string hostRole, string? parentImage, string childImage)
    {
        var bucket = GetBucket(hostRole);
        lock (bucket.Lock)
        {
            if (bucket.Total == 0)
            {
                // No baseline yet at all for this role - treat as maximally uncertain, not maximally rare,
                // so a freshly deployed sensor doesn't flood alerts on day one.
                return 0.5;
            }

            bucket.Counts.TryGetValue(Key(parentImage, childImage), out var count);
            if (count == 0) return 1.0;

            // Rarity falls off smoothly as observation count grows; a lineage seen once in
            // a thousand events is still "rare" but not maximally so.
            var frequency = (double)count / bucket.Total;
            var rarity = 1.0 - Math.Min(1.0, Math.Sqrt(frequency) * 10.0);
            return MathCompat.Clamp(rarity, 0.0, 1.0);
        }
    }

    public void Observe(string hostRole, string? parentImage, string childImage)
    {
        var bucket = GetBucket(hostRole);
        lock (bucket.Lock)
        {
            var key = Key(parentImage, childImage);
            bucket.Counts.TryGetValue(key, out var count);
            bucket.Counts[key] = count + 1;
            bucket.Total++;
        }
    }
}
