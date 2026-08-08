using System.Security.Cryptography;
using Aegis.Core.Diagnostics;
using Aegis.Core.Policy;

namespace Aegis.Service;

/// <summary>
/// Loads the RSA public key the service trusts for policy signatures. Uses the classic
/// .NET Framework XML key-interchange format (<c>RSA.ToXmlString</c>/<c>FromXmlString</c>)
/// rather than PEM, because <c>RSA.ImportFromPem</c> doesn't exist on .NET Framework 4.8 -
/// this format has been stable since .NET Framework 1.1 so it works on every supported OS.
/// If no trust key has been provisioned yet, the service still starts (so a fresh install
/// isn't bricked) but refuses every signed-policy update until an administrator provisions
/// one via the GUI's key-export/install flow - see docs/OPERATIONS.md.
/// </summary>
public sealed class PolicyTrustStore
{
    private readonly string _path;
    private readonly IAegisLogger _logger;
    private RSA? _trustedKey;

    public PolicyTrustStore(string path, IAegisLogger logger)
    {
        _path = path;
        _logger = logger;
        Reload();
    }

    public bool HasTrustedKey => _trustedKey is not null;

    public void Reload()
    {
        _trustedKey?.Dispose();
        _trustedKey = null;

        if (!File.Exists(_path))
        {
            _logger.Warn(nameof(PolicyTrustStore), $"No trusted policy public key at '{_path}'. Signed policy updates will be rejected until one is provisioned.");
            return;
        }

        try
        {
            var xml = File.ReadAllText(_path);
            var rsa = RSA.Create();
            ImportXmlKey(rsa, xml);
            _trustedKey = rsa;
            _logger.Info(nameof(PolicyTrustStore), "Trusted policy public key loaded.");
        }
        catch (Exception ex)
        {
            _logger.Error(nameof(PolicyTrustStore), $"Failed to load trusted policy public key from '{_path}'.", ex);
        }
    }

    public bool Verify(DefensePolicy policy)
    {
        if (_trustedKey is null) return false;
        return PolicySignature.Verify(policy, _trustedKey);
    }

    /// <summary>.NET's cross-platform <see cref="RSA"/> base class dropped the legacy XML
    /// import/export methods from its public surface on some targets; <see cref="RSACryptoServiceProvider"/>
    /// (Windows-only, always available on net48) still has them, so route through it.</summary>
    private static void ImportXmlKey(RSA rsa, string xml)
    {
        using var csp = new RSACryptoServiceProvider();
        csp.FromXmlString(xml);
        rsa.ImportParameters(csp.ExportParameters(false));
    }
}
