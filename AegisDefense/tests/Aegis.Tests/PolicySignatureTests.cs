using System.Security.Cryptography;
using Aegis.Core.Policy;
using Xunit;

namespace Aegis.Tests;

public class PolicySignatureTests
{
    [Fact]
    public void Verify_Succeeds_ForUnmodifiedSignedPolicy()
    {
        using var rsa = RSA.Create(2048);
        var policy = DefensePolicy.CreateDefault("test-issuer");

        PolicySignature.Sign(policy, rsa);

        Assert.True(PolicySignature.Verify(policy, rsa));
    }

    [Fact]
    public void Verify_Fails_WhenPayloadTamperedAfterSigning()
    {
        using var rsa = RSA.Create(2048);
        var policy = DefensePolicy.CreateDefault("test-issuer");
        PolicySignature.Sign(policy, rsa);

        policy.Thresholds.ContainAt = 1; // tamper: try to make containment trivially easy to trigger

        Assert.False(PolicySignature.Verify(policy, rsa));
    }

    [Fact]
    public void Verify_Fails_ForUnsignedPolicy()
    {
        using var rsa = RSA.Create(2048);
        var policy = DefensePolicy.CreateDefault();

        Assert.False(PolicySignature.Verify(policy, rsa));
    }

    [Fact]
    public void Verify_Fails_WithWrongKey()
    {
        using var signingKey = RSA.Create(2048);
        using var otherKey = RSA.Create(2048);
        var policy = DefensePolicy.CreateDefault();

        PolicySignature.Sign(policy, signingKey);

        Assert.False(PolicySignature.Verify(policy, otherKey));
    }

    [Fact]
    public void Verify_Fails_WhenEngineTogglesTampered()
    {
        using var rsa = RSA.Create(2048);
        var policy = DefensePolicy.CreateDefault();
        PolicySignature.Sign(policy, rsa);

        policy.Engines.AutoContainmentEnabled = true; // tamper: silently enable auto-containment

        Assert.False(PolicySignature.Verify(policy, rsa));
    }
}
