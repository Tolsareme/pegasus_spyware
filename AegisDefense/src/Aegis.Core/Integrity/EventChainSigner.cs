using System.Security.Cryptography;
using System.Text;
using Aegis.Core.Events;

namespace Aegis.Core.Integrity;

/// <summary>
/// Hash-chains stored events so tampering or deletion of historical telemetry is
/// detectable (doc §26 risk: "Attacker poisons telemetry or AI context" -> control:
/// "signed telemetry, deterministic evidence validation"). Each event's chain hash is
/// <c>HMAC-SHA256(key, sequence || prevHash || canonical(event))</c>, so recomputing the
/// chain from event #1 forward and comparing hashes reveals exactly the first record an
/// attacker with local DB access modified or removed - the entries before it still verify.
///
/// This raises the bar (an attacker now needs the HMAC key, not just DB write access) but
/// is not a substitute for real telemetry-source authentication; a sufficiently privileged
/// local attacker who also reads the protected key file could still forge a valid chain.
/// It is deliberately scoped as tamper-*evidence*, not tamper-*proofing*.
/// </summary>
public static class EventChainSigner
{
    public const int KeySizeBytes = 32;

    public static byte[] GenerateKey()
    {
        var key = new byte[KeySizeBytes];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(key);
        return key;
    }

    /// <summary>Deterministic byte representation of the fields that matter for integrity - stable across releases as long as this method isn't changed (changing it invalidates all previously-computed chain hashes, by design, since it's meant to be tied to a specific canonicalization).</summary>
    public static byte[] Canonicalize(NormalizedEvent evt)
    {
        var sb = new StringBuilder(256);
        sb.Append(evt.EventId).Append('|')
          .Append(evt.Timestamp.ToUniversalTime().ToString("O")).Append('|')
          .Append(evt.HostId).Append('|')
          .Append(evt.UserId).Append('|')
          .Append(evt.ProcessId).Append('|')
          .Append(evt.ParentProcessId).Append('|')
          .Append(evt.ActionType).Append('|')
          .Append(evt.ObjectType).Append('|')
          .Append(evt.ObjectId).Append('|')
          .Append(evt.SourceIp).Append('|')
          .Append(evt.DestinationIp).Append('|')
          .Append(evt.DestinationPort).Append('|')
          .Append(evt.Result).Append('|')
          .Append(evt.CommandLine);
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    /// <summary>Computes the next link. <paramref name="previousHash"/> should be the genesis constant for the very first event in a chain.</summary>
    public static string ComputeLink(byte[] key, long sequence, string previousHash, NormalizedEvent evt)
    {
        using var hmac = new HMACSHA256(key);
        var seqBytes = BitConverter.GetBytes(sequence);
        var prevBytes = Encoding.UTF8.GetBytes(previousHash);

        using var stream = new MemoryStream();
        stream.Write(seqBytes, 0, seqBytes.Length);
        stream.Write(prevBytes, 0, prevBytes.Length);
        var eventBytes = Canonicalize(evt);
        stream.Write(eventBytes, 0, eventBytes.Length);

        var hash = hmac.ComputeHash(stream.ToArray());
        return Convert.ToBase64String(hash);
    }

    public const string GenesisHash = "GENESIS";
}

public sealed record ChainLink(long Sequence, string PreviousHash, Guid EventId, string ChainHash);

public enum ChainBreakReason
{
    None,
    HashMismatch,      // this record's own data doesn't produce the hash that was stored for it
    PreviousHashMismatch, // this record's stored prev-hash doesn't match the actual previous record's hash - a record was likely deleted, reordered, or its prev-hash column was tampered
    SequenceGap,        // sequence numbers aren't contiguous - a record is missing
}

public sealed record ChainVerificationResult(bool Valid, long? FirstBrokenSequence, ChainBreakReason BreakReason, int LinksChecked);

public static class EventChainVerifier
{
    /// <summary>
    /// Walks the chain in ascending sequence order, propagating the *actual* previous
    /// record's hash forward (not trusting each row's own stored prev-hash column in
    /// isolation) so that deleting or reordering a record is just as detectable as editing
    /// one - a deleted record can't be papered over by leaving its successor's prev-hash
    /// column untouched, because that successor's prev-hash is compared against what the
    /// verifier itself computed for the record before it, and its sequence number is
    /// checked for contiguity.
    /// </summary>
    public static ChainVerificationResult Verify(byte[] key, IEnumerable<(long Sequence, string PreviousHash, string StoredHash, NormalizedEvent Event)> chain)
    {
        var checkedCount = 0;
        var expectedPrevHash = EventChainSigner.GenesisHash;
        long? expectedSequence = null;

        foreach (var (sequence, storedPrevHash, storedHash, evt) in chain)
        {
            checkedCount++;

            if (expectedSequence is not null && sequence != expectedSequence)
            {
                return new ChainVerificationResult(false, sequence, ChainBreakReason.SequenceGap, checkedCount);
            }

            if (!string.Equals(storedPrevHash, expectedPrevHash, StringComparison.Ordinal))
            {
                return new ChainVerificationResult(false, sequence, ChainBreakReason.PreviousHashMismatch, checkedCount);
            }

            var recomputed = EventChainSigner.ComputeLink(key, sequence, expectedPrevHash, evt);
            if (!string.Equals(recomputed, storedHash, StringComparison.Ordinal))
            {
                return new ChainVerificationResult(false, sequence, ChainBreakReason.HashMismatch, checkedCount);
            }

            expectedPrevHash = storedHash;
            expectedSequence = sequence + 1;
        }

        return new ChainVerificationResult(true, null, ChainBreakReason.None, checkedCount);
    }
}
