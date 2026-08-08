namespace Aegis.Data;

/// <summary>Generic <c>Enum.Parse&lt;T&gt;</c> is netstandard2.1+/net5+ only; this project targets netstandard2.0 too (for the net48 host).</summary>
internal static class EnumCompat
{
    public static T Parse<T>(string value) where T : struct, Enum => (T)Enum.Parse(typeof(T), value);
}
