namespace Aegis.Service;

/// <summary>Filesystem layout, kept under ProgramData so it works identically whether the service runs as LocalSystem or a dedicated service account, on any supported Windows version.</summary>
public static class ServiceConfig
{
    public static string RootDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AegisDefense");

    public static string DatabasePath => Path.Combine(RootDirectory, "data", "aegis.db");

    public static string LogDirectory => Path.Combine(RootDirectory, "logs");

    public static string TrustedPolicyPublicKeyPath => Path.Combine(RootDirectory, "keys", "policy-trusted-public.xml");

    public static string EventChainKeyPath => Path.Combine(RootDirectory, "keys", "event-chain.key.protected");

    public const string ServiceName = "AegisDefenseService";
}
