using Aegis.Core.Diagnostics;
using Aegis.Core.Policy;
using Aegis.Ipc;
using Aegis.Ipc.Contracts;

namespace Aegis.Service;

/// <summary>Translates each named-pipe request into a <see cref="DefenseEngine"/> call and shapes the response envelope. Kept separate from DefenseEngine so the engine has zero knowledge of the wire protocol.</summary>
public sealed class IpcRequestHandler
{
    private readonly DefenseEngine _engine;
    private readonly IAegisLogger _logger;

    /// <summary>Message types that change state. An Analyst-role caller (v2 RBAC) may call anything else read-only but is refused these - enforced here, not just hidden in the GUI.</summary>
    private static readonly HashSet<string> MutatingMessageTypes = new(StringComparer.Ordinal)
    {
        MessageTypes.UpdateAlertStatus,
        MessageTypes.SetPolicy,
        MessageTypes.ApproveAction,
        MessageTypes.RejectAction,
        MessageTypes.RegisterDecoy,
        MessageTypes.RemoveDecoy,
    };

    public IpcRequestHandler(DefenseEngine engine, IAegisLogger logger)
    {
        _engine = engine;
        _logger = logger;
    }

    public async Task<IpcEnvelope> HandleAsync(IpcEnvelope request, string? callerRoleRaw, CancellationToken ct)
    {
        // No identifyCaller resolver configured (AegisPipeServer passes null) means RBAC isn't
        // wired up on this deployment - fall back to the pre-RBAC behavior where the pipe's
        // own ACL (Administrators + LocalSystem only) was the sole gate, so every caller who
        // could connect at all is trusted with everything, exactly as before.
        var role = callerRoleRaw is null
            ? OperatorRole.Administrator
            : Enum.TryParse<OperatorRole>(callerRoleRaw, out var parsed) ? parsed : OperatorRole.Unknown;

        if (role == OperatorRole.Unknown)
        {
            _logger.Warn(nameof(IpcRequestHandler), $"Rejected request '{request.MessageType}' from an unrecognized caller (not Administrator or Analyst).");
            return request.CreateErrorResponse("Caller could not be mapped to an authorized role.");
        }

        if (role == OperatorRole.Analyst && MutatingMessageTypes.Contains(request.MessageType))
        {
            return request.CreateErrorResponse($"'{request.MessageType}' requires the Administrator role - this session is Analyst (read-only).");
        }

        try
        {
            switch (request.MessageType)
            {
                case MessageTypes.GetAlerts:
                {
                    var req = request.DeserializePayload<GetAlertsRequest>()!;
                    var alerts = await _engine.GetAlertsAsync(req.HostId, req.StatusFilter, req.Take).ConfigureAwait(false);
                    return request.CreateResponse(MessageTypes.GetAlerts, new GetAlertsResponse(alerts));
                }
                case MessageTypes.UpdateAlertStatus:
                {
                    var req = request.DeserializePayload<UpdateAlertStatusRequest>()!;
                    var ok = await _engine.UpdateAlertStatusAsync(req.AlertId, req.NewStatus).ConfigureAwait(false);
                    return request.CreateResponse(MessageTypes.UpdateAlertStatus, new UpdateAlertStatusResponse(ok));
                }
                case MessageTypes.GetEvents:
                {
                    var req = request.DeserializePayload<GetEventsRequest>()!;
                    var events = await _engine.GetEventsAsync(req.HostId, req.Since, req.Take).ConfigureAwait(false);
                    return request.CreateResponse(MessageTypes.GetEvents, new GetEventsResponse(events));
                }
                case MessageTypes.GetStatistics:
                {
                    var stats = await _engine.GetStatisticsAsync().ConfigureAwait(false);
                    return request.CreateResponse(MessageTypes.GetStatistics, new GetStatisticsResponse(stats));
                }
                case MessageTypes.GetPolicy:
                {
                    return request.CreateResponse(MessageTypes.GetPolicy, new GetPolicyResponse(_engine.GetActivePolicy()));
                }
                case MessageTypes.SetPolicy:
                {
                    var req = request.DeserializePayload<SetPolicyRequest>()!;
                    var (accepted, reason) = await _engine.SetPolicyAsync(req.SignedPolicy).ConfigureAwait(false);
                    return request.CreateResponse(MessageTypes.SetPolicy, new SetPolicyResponse(accepted, reason));
                }
                case MessageTypes.GetPendingApprovals:
                {
                    var approvals = await _engine.GetPendingApprovalsAsync().ConfigureAwait(false);
                    return request.CreateResponse(MessageTypes.GetPendingApprovals, new GetPendingApprovalsResponse(approvals));
                }
                case MessageTypes.ApproveAction:
                {
                    var req = request.DeserializePayload<ApproveActionRequest>()!;
                    var (executed, detail) = await _engine.ApproveActionAsync(req.ApprovalId, req.ApprovedBy).ConfigureAwait(false);
                    return request.CreateResponse(MessageTypes.ApproveAction, new ApproveActionResponse(executed, detail));
                }
                case MessageTypes.RejectAction:
                {
                    var req = request.DeserializePayload<RejectActionRequest>()!;
                    var ok = await _engine.RejectActionAsync(req.ApprovalId, req.RejectedBy, req.Reason).ConfigureAwait(false);
                    return request.CreateResponse(MessageTypes.RejectAction, new RejectActionResponse(ok));
                }
                case MessageTypes.GetGraphNeighborhood:
                {
                    var req = request.DeserializePayload<GetGraphNeighborhoodRequest>()!;
                    var (nodes, edges) = _engine.GetGraphNeighborhood(req.NodeId, req.MaxHops);
                    return request.CreateResponse(MessageTypes.GetGraphNeighborhood, new GetGraphNeighborhoodResponse(nodes, edges));
                }
                case MessageTypes.ListDecoys:
                {
                    return request.CreateResponse(MessageTypes.ListDecoys, new ListDecoysResponse(_engine.ListDecoys()));
                }
                case MessageTypes.RegisterDecoy:
                {
                    var req = request.DeserializePayload<RegisterDecoyRequest>()!;
                    await _engine.RegisterDecoyAsync(req.Decoy).ConfigureAwait(false);
                    return request.CreateResponse(MessageTypes.RegisterDecoy, new RegisterDecoyResponse(true, null));
                }
                case MessageTypes.RemoveDecoy:
                {
                    var req = request.DeserializePayload<RemoveDecoyRequest>()!;
                    var ok = await _engine.RemoveDecoyAsync(req.DecoyId).ConfigureAwait(false);
                    return request.CreateResponse(MessageTypes.RemoveDecoy, new RemoveDecoyResponse(ok));
                }
                case MessageTypes.GetVulnerabilities:
                {
                    var req = request.DeserializePayload<GetVulnerabilitiesRequest>()!;
                    var vulns = await _engine.GetVulnerabilitiesAsync(req.HostId).ConfigureAwait(false);
                    return request.CreateResponse(MessageTypes.GetVulnerabilities, new GetVulnerabilitiesResponse(vulns));
                }
                case MessageTypes.GetServiceHealth:
                {
                    return request.CreateResponse(MessageTypes.GetServiceHealth,
                        new GetServiceHealthResponse(true, "2.0.0", _engine.StartedAt, Array.Empty<string>()));
                }
                case MessageTypes.VerifyEventChain:
                {
                    var result = await _engine.VerifyEventChainAsync().ConfigureAwait(false);
                    return request.CreateResponse(MessageTypes.VerifyEventChain,
                        new VerifyEventChainResponse(result.Valid, result.FirstBrokenSequence, result.BreakReason.ToString(), result.LinksChecked));
                }
                case MessageTypes.WhoAmI:
                {
                    return request.CreateResponse(MessageTypes.WhoAmI, new WhoAmIResponse(role, callerRoleRaw));
                }
                default:
                    return request.CreateErrorResponse($"Unknown message type '{request.MessageType}'.");
            }
        }
        catch (Exception ex)
        {
            _logger.Error(nameof(IpcRequestHandler), $"Error handling '{request.MessageType}'.", ex);
            return request.CreateErrorResponse(ex.Message);
        }
    }
}
