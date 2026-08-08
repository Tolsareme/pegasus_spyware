using Aegis.Core.Events;

namespace Aegis.Core.Features;

/// <summary>
/// Small, centralized classification of "what kind of thing is this event" so the feature
/// engine, rule engine and scoring all agree on the same vocabulary instead of each
/// re-implementing ad-hoc switch statements.
/// </summary>
public static class EventSemantics
{
    public static bool IsPersistenceArtifact(ActionType actionType) => actionType is
        ActionType.ServiceCreate or ActionType.ServiceChange or
        ActionType.ScheduledTaskCreate or ActionType.ScheduledTaskChange or
        ActionType.RegistrySet;

    public static bool IsCredentialSensitive(ActionType actionType) => actionType is
        ActionType.CredentialAccess;

    public static bool IsRemoteAuthentication(ActionType actionType) => actionType is
        ActionType.RemoteAuthentication or ActionType.AuthenticationSuccess;

    public static bool IsDiscoveryLike(ActionType actionType, ObjectType objectType) =>
        actionType is ActionType.NetworkConnect or ActionType.DnsQuery && objectType == ObjectType.NetworkDestination
        || actionType == ActionType.ShareAccess
        || (objectType is ObjectType.UserAccount or ObjectType.ComputerAccount or ObjectType.GroupPolicyObject
            && actionType is ActionType.DirectoryObjectChange);

    public static bool IsFailureAction(NormalizedEvent evt) =>
        evt.Result is ActionResult.Failure or ActionResult.Denied;

    /// <summary>An execution is "suspicious enough to matter" for persistence-timing correlation
    /// if it is rare for the host role and/or shows command obfuscation.</summary>
    public static bool IsSuspiciousExecution(ActionType actionType, double rarity, double complexity) =>
        actionType is ActionType.ProcessCreate or ActionType.ScriptExecution &&
        (rarity >= 0.7 || complexity >= 0.4);
}
