using Aegis.Core.Deception;
using Aegis.Core.Events;
using Xunit;

namespace Aegis.Tests;

public class DeceptionManagerTests
{
    private static NormalizedEvent FileAccessEvent(string hostId, string path) => new()
    {
        EventId = Guid.NewGuid(),
        Timestamp = DateTimeOffset.UtcNow,
        HostId = hostId,
        ActionType = ActionType.FileWrite,
        ObjectId = path,
    };

    [Fact]
    public void TryClassifyCanaryAccess_ReturnsNull_ForNonDecoyPath()
    {
        var manager = new DeceptionManager();
        manager.RegisterDecoy(new DecoyResourceDefinition { Id = "d1", Type = DecoyType.File, Location = @"C:\decoys\passwords.xlsx", Description = "canary" });

        var result = manager.TryClassifyCanaryAccess(FileAccessEvent("host-1", @"C:\Users\alice\notes.txt"));

        Assert.Null(result);
    }

    [Fact]
    public void TryClassifyCanaryAccess_ReclassifiesEvent_ForDecoyPath()
    {
        var manager = new DeceptionManager();
        manager.RegisterDecoy(new DecoyResourceDefinition { Id = "d1", Type = DecoyType.File, Location = @"C:\decoys\passwords.xlsx", Description = "canary" });

        var result = manager.TryClassifyCanaryAccess(FileAccessEvent("host-1", @"C:\decoys\passwords.xlsx"));

        Assert.NotNull(result);
        Assert.Equal(ActionType.CanaryAccess, result!.ActionType);
        Assert.Equal(ObjectType.DecoyResource, result.ObjectType);
        Assert.Equal(1.0, result.Confidence);
    }

    [Fact]
    public void HostScopedDecoy_DoesNotMatch_OnOtherHosts()
    {
        var manager = new DeceptionManager();
        manager.RegisterDecoy(new DecoyResourceDefinition { Id = "d1", Type = DecoyType.File, Location = @"C:\decoys\secret.txt", Description = "canary", HostIdScope = "host-1" });

        Assert.Null(manager.TryClassifyCanaryAccess(FileAccessEvent("host-2", @"C:\decoys\secret.txt")));
        Assert.NotNull(manager.TryClassifyCanaryAccess(FileAccessEvent("host-1", @"C:\decoys\secret.txt")));
    }

    [Fact]
    public void RegisterDecoy_Throws_OnDuplicateId()
    {
        var manager = new DeceptionManager();
        manager.RegisterDecoy(new DecoyResourceDefinition { Id = "d1", Type = DecoyType.File, Location = "loc1", Description = "x" });

        Assert.Throws<InvalidOperationException>(() =>
            manager.RegisterDecoy(new DecoyResourceDefinition { Id = "d1", Type = DecoyType.File, Location = "loc2", Description = "y" }));
    }

    [Fact]
    public void Decoy_NeverGrantsRealPrivilege()
    {
        var decoy = new DecoyResourceDefinition { Id = "d1", Type = DecoyType.HoneyCredential, Location = "svc-account", Description = "honey cred" };
        Assert.False(decoy.GrantsRealPrivilege);
    }

    [Fact]
    public async Task NullDecoyMaterializer_MaterializeAsync_ReturnsExplanatoryFailure()
    {
        var materializer = new NullDecoyMaterializer();
        var decoy = new DecoyResourceDefinition { Id = "d1", Type = DecoyType.File, Location = @"C:\decoys\passwords.xlsx", Description = "canary" };

        var result = await materializer.MaterializeAsync(decoy);

        Assert.False(result.Success);
        Assert.Contains("No decoy materializer", result.Detail);
    }

    [Fact]
    public async Task NullDecoyMaterializer_RemoveAsync_SucceedsAsNoOp()
    {
        var materializer = new NullDecoyMaterializer();
        var decoy = new DecoyResourceDefinition { Id = "d1", Type = DecoyType.File, Location = @"C:\decoys\passwords.xlsx", Description = "canary" };

        var result = await materializer.RemoveAsync(decoy);

        Assert.True(result.Success);
    }
}
