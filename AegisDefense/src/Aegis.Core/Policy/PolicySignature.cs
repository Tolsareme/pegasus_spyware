using System.Security.Cryptography;
using System.Text.Json;

namespace Aegis.Core.Policy;

/// <summary>
/// Signs and verifies <see cref="DefensePolicy"/> documents with RSA-SHA256 so a policy
/// cannot be silently edited on disk or in transit between the GUI and the service -
/// doc §29 "execution should occur only through a narrow, deterministic response API
/// with signed policies". Deliberately uses only BCL cryptography (no extra NuGet
/// dependency) so it runs unmodified on Windows 7 SP1 through Server 2025.
/// </summary>
public static class PolicySignature
{
    private static readonly JsonSerializerOptions CanonicalOptions = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never,
    };

    /// <summary>The exact bytes that get signed/verified: every field of the policy except the signature itself.</summary>
    public static byte[] GetCanonicalPayload(DefensePolicy policy)
    {
        var unsigned = Clone(policy);
        unsigned.Signature = null;
        var json = JsonSerializer.Serialize(unsigned, CanonicalOptions);
        return System.Text.Encoding.UTF8.GetBytes(json);
    }

    public static void Sign(DefensePolicy policy, RSA privateKey)
    {
        var payload = GetCanonicalPayload(policy);
        var signature = privateKey.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        policy.Signature = Convert.ToBase64String(signature);
    }

    public static bool Verify(DefensePolicy policy, RSA publicKey)
    {
        if (string.IsNullOrWhiteSpace(policy.Signature)) return false;

        byte[] signatureBytes;
        try
        {
            signatureBytes = Convert.FromBase64String(policy.Signature);
        }
        catch (FormatException)
        {
            return false;
        }

        var payload = GetCanonicalPayload(policy);
        return publicKey.VerifyData(payload, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private static DefensePolicy Clone(DefensePolicy policy)
    {
        var json = JsonSerializer.Serialize(policy, CanonicalOptions);
        return JsonSerializer.Deserialize<DefensePolicy>(json, CanonicalOptions)
               ?? throw new InvalidOperationException("Policy round-trip serialization failed.");
    }
}
