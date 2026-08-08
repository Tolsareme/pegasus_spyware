#if NETSTANDARD2_0
// Minimal compiler-support polyfills so C# 9-11 features (init-only setters, records,
// required members) can be used while targeting netstandard2.0 - needed because .NET
// Framework 4.8 (the "old Windows machine" target for this solution) can only consume a
// netstandard2.0 library, not a net8.0 one, and these marker types normally only ship
// with newer BCLs. Public (not internal) so Aegis.Ipc / Aegis.Data, which reference
// Aegis.Core, resolve the same types instead of needing their own copies.
// This is the same technique the PolySharp NuGet package automates; hand-rolled here to
// avoid an extra external dependency for four small marker types.

namespace System.Runtime.CompilerServices
{
    public static class IsExternalInit { }

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct | AttributeTargets.Field | AttributeTargets.Property, Inherited = false, AllowMultiple = true)]
    public sealed class RequiredMemberAttribute : Attribute { }

    [AttributeUsage(AttributeTargets.All, Inherited = false, AllowMultiple = true)]
    public sealed class CompilerFeatureRequiredAttribute : Attribute
    {
        public CompilerFeatureRequiredAttribute(string featureName) => FeatureName = featureName;
        public string FeatureName { get; }
    }
}

namespace System.Diagnostics.CodeAnalysis
{
    [AttributeUsage(AttributeTargets.Constructor, Inherited = false)]
    public sealed class SetsRequiredMembersAttribute : Attribute { }
}
#endif
