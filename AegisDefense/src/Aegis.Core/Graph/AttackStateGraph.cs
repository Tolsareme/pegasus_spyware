using Aegis.Core.Events;

namespace Aegis.Core.Graph;

/// <summary>
/// The "continuously updated graph" from doc §9: nodes for hosts, identities, processes,
/// files, services, destinations; edges for the actions between them. Answers not just
/// "what happened" but "what campaign is forming" by letting callers walk from any node
/// outward. Kept as a simple in-memory structure for the MVP - doc §20 calls out a
/// graph-capable store as the production target; this class is the seam an
/// <c>IAttackStateGraph</c>-backed store could implement identically later.
/// </summary>
public sealed class AttackStateGraph
{
    private readonly Dictionary<string, GraphNode> _nodes = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<GraphEdge> _edges = new();
    private readonly TimeSpan _retention;

    public AttackStateGraph(TimeSpan? retention = null)
    {
        _retention = retention ?? TimeSpan.FromHours(24);
    }

    public IReadOnlyCollection<GraphNode> Nodes => _nodes.Values;
    public IReadOnlyList<GraphEdge> Edges => _edges;

    /// <summary>Derives nodes/edges implied by one normalized event and merges them into the graph. Returns the edges added (0-2 typically).</summary>
    public IReadOnlyList<GraphEdge> AddEvent(NormalizedEvent evt)
    {
        Trim(evt.Timestamp);

        var added = new List<GraphEdge>(2);
        var hostNode = Upsert(evt.HostId, GraphNodeType.Host, evt.Timestamp);

        if (evt.UserId is not null)
        {
            var identityNode = Upsert(evt.UserId, GraphNodeType.Identity, evt.Timestamp);
            if (evt.ActionType is ActionType.AuthenticationSuccess or ActionType.RemoteAuthentication)
            {
                added.Add(Connect(identityNode, hostNode, GraphEdgeType.LogsOnTo, evt));
            }
        }

        string? processNodeId = null;
        if (evt.ProcessId is not null)
        {
            processNodeId = $"{evt.HostId}!pid:{evt.ProcessId}:{evt.ImagePath ?? "?"}";
            var processNode = Upsert(processNodeId, GraphNodeType.Process, evt.Timestamp);
            if (evt.ActionType == ActionType.ProcessCreate)
            {
                added.Add(Connect(hostNode, processNode, GraphEdgeType.Spawns, evt));
            }
        }

        switch (evt.ActionType)
        {
            case ActionType.FileCreate or ActionType.FileWrite or ActionType.FileRename when evt.ObjectId is not null && processNodeId is not null:
                {
                    var fileNode = Upsert(evt.ObjectId, GraphNodeType.File, evt.Timestamp);
                    added.Add(Connect(_nodes[processNodeId], fileNode, GraphEdgeType.Writes, evt));
                    break;
                }
            case ActionType.FileDelete when evt.ObjectId is not null && processNodeId is not null:
                {
                    var fileNode = Upsert(evt.ObjectId, GraphNodeType.File, evt.Timestamp);
                    added.Add(Connect(_nodes[processNodeId], fileNode, GraphEdgeType.Deletes, evt));
                    break;
                }
            case ActionType.NetworkConnect when evt.DestinationIp is not null && processNodeId is not null:
                {
                    var destNode = Upsert(evt.DestinationIp, GraphNodeType.Destination, evt.Timestamp);
                    added.Add(Connect(_nodes[processNodeId], destNode, GraphEdgeType.ConnectsTo, evt));
                    break;
                }
            case ActionType.ServiceCreate or ActionType.ScheduledTaskCreate when evt.ObjectId is not null && processNodeId is not null:
                {
                    var nodeType = evt.ActionType == ActionType.ServiceCreate ? GraphNodeType.Service : GraphNodeType.ScheduledTask;
                    var svcNode = Upsert(evt.ObjectId, nodeType, evt.Timestamp);
                    added.Add(Connect(_nodes[processNodeId], svcNode, GraphEdgeType.Creates, evt));
                    break;
                }
            case ActionType.CredentialAccess when evt.ObjectId is not null && processNodeId is not null:
                {
                    var credNode = Upsert(evt.ObjectId, GraphNodeType.Credential, evt.Timestamp);
                    added.Add(Connect(_nodes[processNodeId], credNode, GraphEdgeType.Accesses, evt));
                    break;
                }
            case ActionType.CanaryAccess when evt.ObjectId is not null:
                {
                    var decoyNode = Upsert(evt.ObjectId, GraphNodeType.DecoyResource, evt.Timestamp);
                    added.Add(Connect(hostNode, decoyNode, GraphEdgeType.Accesses, evt));
                    break;
                }
        }

        return added;
    }

    /// <summary>Breadth-first walk outward from a node - the mechanism behind "what campaign is forming".</summary>
    public IReadOnlyList<GraphNode> Neighborhood(string nodeId, int maxHops = 2)
    {
        if (!_nodes.ContainsKey(nodeId)) return Array.Empty<GraphNode>();

        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { nodeId };
        var frontier = new Queue<(string Id, int Hops)>();
        frontier.Enqueue((nodeId, 0));
        var result = new List<GraphNode>();

        while (frontier.Count > 0)
        {
            var (id, hops) = frontier.Dequeue();
            if (hops >= maxHops) continue;

            foreach (var edge in _edges.Where(e => e.FromId == id || e.ToId == id))
            {
                var otherId = edge.FromId == id ? edge.ToId : edge.FromId;
                if (visited.Add(otherId) && _nodes.TryGetValue(otherId, out var node))
                {
                    result.Add(node);
                    frontier.Enqueue((otherId, hops + 1));
                }
            }
        }

        return result;
    }

    private GraphNode Upsert(string id, GraphNodeType type, DateTimeOffset at)
    {
        if (_nodes.TryGetValue(id, out var existing))
        {
            var updated = existing with { LastSeen = at };
            _nodes[id] = updated;
            return updated;
        }

        var created = new GraphNode { Id = id, Type = type, FirstSeen = at, LastSeen = at };
        _nodes[id] = created;
        return created;
    }

    private GraphEdge Connect(GraphNode from, GraphNode to, GraphEdgeType type, NormalizedEvent evt)
    {
        var edge = new GraphEdge
        {
            FromId = from.Id,
            ToId = to.Id,
            Type = type,
            Timestamp = evt.Timestamp,
            SourceEventId = evt.EventId,
        };
        _edges.Add(edge);
        return edge;
    }

    private void Trim(DateTimeOffset now)
    {
        var cutoff = now - _retention;
        if (_edges.Count == 0 || _edges[0].Timestamp >= cutoff) return;

        _edges.RemoveAll(e => e.Timestamp < cutoff);

        var reachable = new HashSet<string>(_edges.SelectMany(e => new[] { e.FromId, e.ToId }), StringComparer.OrdinalIgnoreCase);
        var stale = _nodes.Values.Where(n => n.LastSeen < cutoff && !reachable.Contains(n.Id)).Select(n => n.Id).ToList();
        foreach (var id in stale) _nodes.Remove(id);
    }
}
