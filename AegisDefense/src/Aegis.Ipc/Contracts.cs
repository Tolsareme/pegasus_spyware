using Aegis.Core.Deception;
using Aegis.Core.Estimation;
using Aegis.Core.Events;
using Aegis.Core.Graph;
using Aegis.Core.Patching;
using Aegis.Core.Policy;
using Aegis.Core.Vulnerability;

namespace Aegis.Ipc.Contracts;

/// <summary>
/// Every message type name used on the wire, grouped so client and server can't typo a
/// route. Naming convention: "&lt;Verb&gt;" for the request, response mirrors it 1:1.
/// </summary>
public static class MessageTypes
{
    public const string GetAlerts = "GetAlerts";
    public const string UpdateAlertStatus = "UpdateAlertStatus";
    public const string GetEvents = "GetEvents";
    public const string GetStatistics = "GetStatistics";
    public const string GetPolicy = "GetPolicy";
    public const string SetPolicy = "SetPolicy";
    public const string GetPendingApprovals = "GetPendingApprovals";
    public const string ApproveAction = "ApproveAction";
    public const string RejectAction = "RejectAction";
    public const string GetGraphNeighborhood = "GetGraphNeighborhood";
    public const string GetAttackStateSnapshots = "GetAttackStateSnapshots";
    public const string ListDecoys = "ListDecoys";
    public const string RegisterDecoy = "RegisterDecoy";
    public const string RemoveDecoy = "RemoveDecoy";
    public const string GetVulnerabilities = "GetVulnerabilities";
    public const string GetServiceHealth = "GetServiceHealth";
    public const string VerifyEventChain = "VerifyEventChain";
    public const string WhoAmI = "WhoAmI";
    public const string GetHostInventory = "GetHostInventory";
    public const string ListPatchPlans = "ListPatchPlans";
    public const string CreatePatchPlan = "CreatePatchPlan";
    public const string ApplyPatchMitigation = "ApplyPatchMitigation";
    public const string BeginPatchCanaryTesting = "BeginPatchCanaryTesting";
    public const string RecordPatchCanaryHealthCheck = "RecordPatchCanaryHealthCheck";
    public const string BeginPatchRingDeployment = "BeginPatchRingDeployment";
    public const string RecordPatchRingHealthCheck = "RecordPatchRingHealthCheck";
    public const string ClosePatchMitigation = "ClosePatchMitigation";
    public const string RollbackPatchPlan = "RollbackPatchPlan";
    public const string ExecuteAlertAction = "ExecuteAlertAction";
}

public sealed record ExecuteAlertActionRequest(Guid AlertId, AlertActionKind Action);
public sealed record ExecuteAlertActionResponse(bool Success, string Detail, IReadOnlyList<string> ActionsTaken);

public sealed record GetAlertsRequest(string? HostId, AlertStatus? StatusFilter, int Take = 200);
public sealed record GetAlertsResponse(IReadOnlyList<Alert> Alerts);

public sealed record UpdateAlertStatusRequest(Guid AlertId, AlertStatus NewStatus, string ChangedBy);
public sealed record UpdateAlertStatusResponse(bool Success);

public sealed record GetEventsRequest(string? HostId, DateTimeOffset? Since, int Take = 500);
public sealed record GetEventsResponse(IReadOnlyList<NormalizedEvent> Events);

public sealed record EngineStatus(string Name, bool Enabled, string? Detail);

public sealed record StatisticsSnapshot(
    DateTimeOffset AsOf,
    int TotalHostsMonitored,
    int EventsLast24h,
    int AlertsLast24h,
    int OpenAlerts,
    int CriticalAlerts,
    double AverageHostRisk,
    IReadOnlyList<EngineStatus> Engines,
    TimeSpan ServiceUptime,
    IReadOnlyDictionary<string, int> AlertsBySeverity,
    IReadOnlyDictionary<string, int> HostsByAttackState);

public sealed record GetStatisticsRequest;
public sealed record GetStatisticsResponse(StatisticsSnapshot Statistics);

public sealed record GetPolicyRequest;
public sealed record GetPolicyResponse(DefensePolicy Policy);

/// <summary>Policy must already be signed by the caller (the GUI, using an operator-held key) before being sent - the service only ever verifies, it never signs on the caller's behalf.</summary>
public sealed record SetPolicyRequest(DefensePolicy SignedPolicy);
public sealed record SetPolicyResponse(bool Accepted, string? RejectionReason);

public sealed record GetPendingApprovalsRequest;
public sealed record GetPendingApprovalsResponse(IReadOnlyList<PendingApproval> Approvals);

public sealed record ApproveActionRequest(Guid ApprovalId, string ApprovedBy);
public sealed record ApproveActionResponse(bool Executed, string? Detail);

public sealed record RejectActionRequest(Guid ApprovalId, string RejectedBy, string? Reason);
public sealed record RejectActionResponse(bool Success);

public sealed record GetGraphNeighborhoodRequest(string NodeId, int MaxHops = 2);
public sealed record GetGraphNeighborhoodResponse(IReadOnlyList<GraphNode> Nodes, IReadOnlyList<GraphEdge> Edges);

public sealed record GetAttackStateSnapshotsRequest(string? HostId);
public sealed record GetAttackStateSnapshotsResponse(IReadOnlyList<AttackStateSnapshot> Snapshots);

public sealed record ListDecoysRequest;
public sealed record ListDecoysResponse(IReadOnlyList<DecoyResourceDefinition> Decoys);

public sealed record RegisterDecoyRequest(DecoyResourceDefinition Decoy);
public sealed record RegisterDecoyResponse(bool Success, string? Error);

public sealed record RemoveDecoyRequest(string DecoyId);
public sealed record RemoveDecoyResponse(bool Success);

public sealed record GetVulnerabilitiesRequest(string? HostId);
public sealed record GetVulnerabilitiesResponse(IReadOnlyList<VulnerabilityPriority> Vulnerabilities);

public sealed record GetServiceHealthRequest;
public sealed record GetServiceHealthResponse(bool Healthy, string Version, DateTimeOffset StartedAt, IReadOnlyList<string> Warnings);

public sealed record VerifyEventChainRequest;
public sealed record VerifyEventChainResponse(bool Valid, long? FirstBrokenSequence, string? BreakReason, int LinksChecked);

public sealed record WhoAmIRequest;
public sealed record WhoAmIResponse(OperatorRole Role, string? WindowsIdentity);

public sealed record HostInventoryEntry(string HostId, DateTimeOffset LastSeen, int EventCount24h, string? CurrentAttackState, int OpenAlertCount);
public sealed record GetHostInventoryRequest;
public sealed record GetHostInventoryResponse(IReadOnlyList<HostInventoryEntry> Hosts);

/// <summary>Wraps the outcome of any single patch-plan orchestration call - a rejected
/// transition (e.g. "wrong stage") is reported via Error/Plan (the plan unchanged), never an
/// exception over the wire.</summary>
public sealed record PatchPlanActionResponse(bool Success, string? Error, PatchRolloutPlan? Plan);

public sealed record ListPatchPlansRequest;
public sealed record ListPatchPlansResponse(IReadOnlyList<PatchRolloutPlan> Plans);

public sealed record CreatePatchPlanRequest(string Component, string VendorAdvisoryReference, IReadOnlyList<RingDefinition> Rings);

public sealed record ApplyPatchMitigationRequest(Guid PlanId, string Reason);
public sealed record BeginPatchCanaryTestingRequest(Guid PlanId, string Reason);
public sealed record RecordPatchCanaryHealthCheckRequest(Guid PlanId, HealthCheckResult Result);
public sealed record BeginPatchRingDeploymentRequest(Guid PlanId, string Reason);
public sealed record RecordPatchRingHealthCheckRequest(Guid PlanId, HealthCheckResult Result);
public sealed record ClosePatchMitigationRequest(Guid PlanId, string Reason);
public sealed record RollbackPatchPlanRequest(Guid PlanId, string Reason);
