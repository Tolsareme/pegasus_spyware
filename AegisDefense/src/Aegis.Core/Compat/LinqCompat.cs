#if NETSTANDARD2_0
namespace Aegis.Core.Compat;

/// <summary>Minimal <c>MaxBy</c> shim for netstandard2.0, where <see cref="System.Linq.Enumerable"/> doesn't have it yet (added in .NET 6). Only compiled in on netstandard2.0 so it never collides with the real BCL extension on net8.0.</summary>
internal static class LinqCompat
{
    public static TSource MaxBy<TSource, TKey>(this IEnumerable<TSource> source, Func<TSource, TKey> keySelector)
        where TKey : IComparable<TKey>
    {
        using var e = source.GetEnumerator();
        if (!e.MoveNext()) throw new InvalidOperationException("Sequence contains no elements.");

        var best = e.Current;
        var bestKey = keySelector(best);
        while (e.MoveNext())
        {
            var key = keySelector(e.Current);
            if (key.CompareTo(bestKey) > 0)
            {
                best = e.Current;
                bestKey = key;
            }
        }
        return best;
    }
}
#endif
