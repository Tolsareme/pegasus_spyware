using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Gui.Services;

/// <summary>
/// Owns the operator's policy-signing RSA key pair. The private key is protected at rest
/// with Windows DPAPI (<see cref="ProtectedData"/>, <see cref="DataProtectionScope.CurrentUser"/>)
/// so it never sits on disk in plaintext and cannot be reused if copied to another machine
/// or account (doc §29's "signed policies" requirement needs a key the service can verify
/// against but that only this operator can produce signatures with). The public key is
/// exported in the classic XML interchange format so <c>Aegis.Service</c>'s
/// <c>PolicyTrustStore</c> (net48, same format) can load it without any extra dependency.
/// </summary>
public sealed class PolicySigningKeyManager
{
    private readonly string _protectedKeyPath;

    public PolicySigningKeyManager(string? protectedKeyPath = null)
    {
        _protectedKeyPath = protectedKeyPath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "AegisDefense", "policy-signing-key.protected");
    }

    public bool HasKey => File.Exists(_protectedKeyPath);

    /// <summary>Generates a new 2048-bit signing key, overwriting any existing one. Callers should warn the operator that this invalidates trust with any service that already has the old public key installed.</summary>
    public RSA GenerateNewKey()
    {
        var rsa = RSA.Create(2048);
        Persist(rsa);
        return rsa;
    }

    public RSA LoadKey()
    {
        if (!HasKey) throw new InvalidOperationException("No policy signing key has been generated yet.");

        var protectedBytes = File.ReadAllBytes(_protectedKeyPath);
        var xmlBytes = ProtectedData.Unprotect(protectedBytes, optionalEntropy: null, scope: DataProtectionScope.CurrentUser);
        var xml = Encoding.UTF8.GetString(xmlBytes);

        var rsa = RSA.Create();
        using var csp = new RSACryptoServiceProvider();
        csp.FromXmlString(xml);
        rsa.ImportParameters(csp.ExportParameters(includePrivateParameters: true));
        return rsa;
    }

    public string ExportPublicKeyXml(RSA rsa)
    {
        using var csp = new RSACryptoServiceProvider();
        csp.ImportParameters(rsa.ExportParameters(includePrivateParameters: false));
        return csp.ToXmlString(includePrivateParameters: false);
    }

    /// <summary>Writes the public key to a file an administrator copies to the service host's <c>ServiceConfig.TrustedPolicyPublicKeyPath</c> during provisioning.</summary>
    public void ExportPublicKeyToFile(RSA rsa, string destinationPath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(destinationPath)!);
        File.WriteAllText(destinationPath, ExportPublicKeyXml(rsa), Encoding.UTF8);
    }

    private void Persist(RSA rsa)
    {
        using var csp = new RSACryptoServiceProvider();
        csp.ImportParameters(rsa.ExportParameters(includePrivateParameters: true));
        var xml = csp.ToXmlString(includePrivateParameters: true);
        var xmlBytes = Encoding.UTF8.GetBytes(xml);
        var protectedBytes = ProtectedData.Protect(xmlBytes, optionalEntropy: null, scope: DataProtectionScope.CurrentUser);

        Directory.CreateDirectory(Path.GetDirectoryName(_protectedKeyPath)!);
        File.WriteAllBytes(_protectedKeyPath, protectedBytes);
    }
}
