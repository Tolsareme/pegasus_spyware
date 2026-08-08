using System.Security.Cryptography;
using Aegis.Core.Diagnostics;
using Aegis.Core.Integrity;

namespace Aegis.Service;

/// <summary>
/// Loads (or, on first run, generates and persists) the HMAC key used to hash-chain stored
/// events. Protected with DPAPI at <see cref="DataProtectionScope.LocalMachine"/> - not
/// <c>CurrentUser</c> like the GUI's policy-signing key - because the service runs as
/// LocalSystem and must be able to decrypt it with no interactive user logged on.
/// </summary>
public sealed class EventChainKeyStore
{
    private readonly string _path;
    private readonly IAegisLogger _logger;

    public EventChainKeyStore(string path, IAegisLogger logger)
    {
        _path = path;
        _logger = logger;
    }

    public byte[] LoadOrCreate()
    {
        if (File.Exists(_path))
        {
            try
            {
                var protectedBytes = File.ReadAllBytes(_path);
                var key = ProtectedData.Unprotect(protectedBytes, optionalEntropy: null, scope: DataProtectionScope.LocalMachine);
                _logger.Info(nameof(EventChainKeyStore), "Loaded existing event-chain integrity key.");
                return key;
            }
            catch (Exception ex)
            {
                _logger.Error(nameof(EventChainKeyStore), $"Failed to load event-chain key from '{_path}' - a new one will be generated, which breaks continuity with any previously-chained events (they'll still verify up to this point, just not link to what comes after).", ex);
            }
        }

        var newKey = EventChainSigner.GenerateKey();
        Persist(newKey);
        _logger.Info(nameof(EventChainKeyStore), "Generated new event-chain integrity key.");
        return newKey;
    }

    private void Persist(byte[] key)
    {
        var protectedBytes = ProtectedData.Protect(key, optionalEntropy: null, scope: DataProtectionScope.LocalMachine);
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        File.WriteAllBytes(_path, protectedBytes);
    }
}
