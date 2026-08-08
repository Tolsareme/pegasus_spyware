using Aegis.Core.Events;
using Aegis.Core.Integrity;
using Xunit;

namespace Aegis.Tests;

public class EventChainTests
{
    private static NormalizedEvent MakeEvent(string hostId = "host-1", string? cmd = null) => new()
    {
        EventId = Guid.NewGuid(),
        Timestamp = DateTimeOffset.UtcNow,
        HostId = hostId,
        ActionType = ActionType.ProcessCreate,
        CommandLine = cmd,
    };

    private static List<(long Sequence, string PreviousHash, string ChainHash, NormalizedEvent Event)> BuildChain(byte[] key, int count)
    {
        var chain = new List<(long, string, string, NormalizedEvent)>();
        var prevHash = EventChainSigner.GenesisHash;
        for (var i = 0; i < count; i++)
        {
            var evt = MakeEvent(cmd: $"cmd-{i}");
            var hash = EventChainSigner.ComputeLink(key, i, prevHash, evt);
            chain.Add((i, prevHash, hash, evt));
            prevHash = hash;
        }
        return chain;
    }

    [Fact]
    public void ComputeLink_IsDeterministic_ForSameInputs()
    {
        var key = EventChainSigner.GenerateKey();
        var evt = MakeEvent();

        var hash1 = EventChainSigner.ComputeLink(key, 0, EventChainSigner.GenesisHash, evt);
        var hash2 = EventChainSigner.ComputeLink(key, 0, EventChainSigner.GenesisHash, evt);

        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void ComputeLink_Differs_WhenEventContentDiffers()
    {
        var key = EventChainSigner.GenerateKey();
        var evt1 = MakeEvent(cmd: "whoami");
        var evt2 = MakeEvent(cmd: "net user administrator /active:yes");

        var hash1 = EventChainSigner.ComputeLink(key, 0, EventChainSigner.GenesisHash, evt1);
        var hash2 = EventChainSigner.ComputeLink(key, 0, EventChainSigner.GenesisHash, evt2);

        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void ComputeLink_Differs_WithDifferentKey()
    {
        var evt = MakeEvent();
        var hash1 = EventChainSigner.ComputeLink(EventChainSigner.GenerateKey(), 0, EventChainSigner.GenesisHash, evt);
        var hash2 = EventChainSigner.ComputeLink(EventChainSigner.GenerateKey(), 0, EventChainSigner.GenesisHash, evt);

        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void Verify_Succeeds_ForUntamperedChain()
    {
        var key = EventChainSigner.GenerateKey();
        var chain = BuildChain(key, 10);

        var result = EventChainVerifier.Verify(key, chain);

        Assert.True(result.Valid);
        Assert.Equal(10, result.LinksChecked);
    }

    [Fact]
    public void Verify_Fails_WhenAnEventFieldIsTamperedAfterTheFact()
    {
        var key = EventChainSigner.GenerateKey();
        var chain = BuildChain(key, 10);

        // Tamper with record 5's content without recomputing its hash (the attacker doesn't have the key).
        var tampered = chain[5].Event with { CommandLine = "malicious-rewrite" };
        chain[5] = (chain[5].Sequence, chain[5].PreviousHash, chain[5].ChainHash, tampered);

        var result = EventChainVerifier.Verify(key, chain);

        Assert.False(result.Valid);
        Assert.Equal(5, result.FirstBrokenSequence);
        Assert.Equal(ChainBreakReason.HashMismatch, result.BreakReason);
    }

    [Fact]
    public void Verify_Fails_WhenARecordIsDeleted()
    {
        var key = EventChainSigner.GenerateKey();
        var chain = BuildChain(key, 10);

        chain.RemoveAt(5); // simulate an attacker deleting one row directly from the database

        var result = EventChainVerifier.Verify(key, chain);

        Assert.False(result.Valid);
        // The record that used to be at position 6 now appears right after position 4,
        // so either its sequence number or its prev-hash will no longer match expectations.
        Assert.True(result.BreakReason is ChainBreakReason.SequenceGap or ChainBreakReason.PreviousHashMismatch);
    }

    [Fact]
    public void Verify_Fails_WithWrongKey()
    {
        var key = EventChainSigner.GenerateKey();
        var chain = BuildChain(key, 5);

        var result = EventChainVerifier.Verify(EventChainSigner.GenerateKey(), chain);

        Assert.False(result.Valid);
        Assert.Equal(0, result.FirstBrokenSequence);
    }

    [Fact]
    public void Verify_SucceedsOnEmptyChain()
    {
        var result = EventChainVerifier.Verify(EventChainSigner.GenerateKey(),
            Array.Empty<(long, string, string, NormalizedEvent)>());

        Assert.True(result.Valid);
        Assert.Equal(0, result.LinksChecked);
    }
}
