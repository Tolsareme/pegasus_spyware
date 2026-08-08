using Aegis.Core.Events;
using Aegis.Core.Graph;
using Xunit;

namespace Aegis.Tests;

public class AttackStateGraphTests
{
    [Fact]
    public void AddEvent_CreatesSpawnsEdge_ForProcessCreate()
    {
        var graph = new AttackStateGraph();
        var evt = new NormalizedEvent
        {
            EventId = Guid.NewGuid(),
            Timestamp = DateTimeOffset.UtcNow,
            HostId = "host-1",
            ProcessId = 4242,
            ImagePath = "cmd.exe",
            ActionType = ActionType.ProcessCreate,
        };

        var added = graph.AddEvent(evt);

        Assert.Single(added);
        Assert.Equal(GraphEdgeType.Spawns, added[0].Type);
        Assert.Contains(graph.Nodes, n => n.Type == GraphNodeType.Host && n.Id == "host-1");
        Assert.Contains(graph.Nodes, n => n.Type == GraphNodeType.Process);
    }

    [Fact]
    public void AddEvent_CreatesConnectsToEdge_ForNetworkConnect()
    {
        var graph = new AttackStateGraph();
        var hostId = "host-1";
        var processId = 100;

        graph.AddEvent(new NormalizedEvent
        {
            EventId = Guid.NewGuid(), Timestamp = DateTimeOffset.UtcNow, HostId = hostId,
            ProcessId = processId, ImagePath = "svchost.exe", ActionType = ActionType.ProcessCreate,
        });

        var connectEdges = graph.AddEvent(new NormalizedEvent
        {
            EventId = Guid.NewGuid(), Timestamp = DateTimeOffset.UtcNow, HostId = hostId,
            ProcessId = processId, ImagePath = "svchost.exe", ActionType = ActionType.NetworkConnect,
            DestinationIp = "10.0.0.9",
        });

        Assert.Single(connectEdges);
        Assert.Equal(GraphEdgeType.ConnectsTo, connectEdges[0].Type);
        Assert.Contains(graph.Nodes, n => n.Type == GraphNodeType.Destination && n.Id == "10.0.0.9");
    }

    [Fact]
    public void Neighborhood_FindsConnectedNodes_WithinHopLimit()
    {
        var graph = new AttackStateGraph();
        var hostId = "host-1";

        graph.AddEvent(new NormalizedEvent
        {
            EventId = Guid.NewGuid(), Timestamp = DateTimeOffset.UtcNow, HostId = hostId,
            ProcessId = 1, ImagePath = "a.exe", ActionType = ActionType.ProcessCreate,
        });
        graph.AddEvent(new NormalizedEvent
        {
            EventId = Guid.NewGuid(), Timestamp = DateTimeOffset.UtcNow, HostId = hostId,
            ProcessId = 1, ImagePath = "a.exe", ObjectId = "10.1.1.1", ActionType = ActionType.NetworkConnect,
            DestinationIp = "10.1.1.1",
        });

        var neighborhood = graph.Neighborhood(hostId, maxHops: 2);

        Assert.Contains(neighborhood, n => n.Type == GraphNodeType.Process);
        Assert.Contains(neighborhood, n => n.Type == GraphNodeType.Destination);
    }

    [Fact]
    public void CanaryAccess_CreatesDecoyResourceNode()
    {
        var graph = new AttackStateGraph();
        graph.AddEvent(new NormalizedEvent
        {
            EventId = Guid.NewGuid(), Timestamp = DateTimeOffset.UtcNow, HostId = "host-1",
            ActionType = ActionType.CanaryAccess, ObjectType = ObjectType.DecoyResource, ObjectId = "decoy-1",
        });

        Assert.Contains(graph.Nodes, n => n.Type == GraphNodeType.DecoyResource && n.Id == "decoy-1");
    }
}
