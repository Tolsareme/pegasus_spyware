namespace Aegis.Core.Events;

/// <summary>
/// Broad category of an observed action. Kept small and stable so correlation logic
/// does not depend on any single Windows telemetry provider (doc §6 "Normalized Event Model").
/// </summary>
public enum ActionType
{
    Unknown = 0,
    ProcessCreate,
    ProcessTerminate,
    ImageLoad,
    ScriptExecution,
    AuthenticationSuccess,
    AuthenticationFailure,
    LogonTypeChange,
    PrivilegeAssigned,
    PrivilegeUse,
    NetworkConnect,
    NetworkListen,
    DnsQuery,
    FileCreate,
    FileWrite,
    FileDelete,
    FileRename,
    RegistrySet,
    RegistryDelete,
    ServiceCreate,
    ServiceChange,
    ScheduledTaskCreate,
    ScheduledTaskChange,
    CredentialAccess,
    RemoteAuthentication,
    DriverLoad,
    SecurityControlChange,
    DirectoryObjectChange,
    ShareAccess,
    CanaryAccess,
}

/// <summary>The kind of entity an action was performed against.</summary>
public enum ObjectType
{
    Unknown = 0,
    Process,
    File,
    RegistryKey,
    Service,
    ScheduledTask,
    UserAccount,
    ComputerAccount,
    GroupPolicyObject,
    Share,
    NetworkDestination,
    Credential,
    Driver,
    SecurityControl,
    DecoyResource,
}

/// <summary>Outcome of the attempted action, as observed by the sensor.</summary>
public enum ActionResult
{
    Unknown = 0,
    Success,
    Failure,
    Denied,
}

/// <summary>
/// Attacker objective / MITRE-ATT&amp;CK-like stage used for attack-state estimation
/// (doc §10 "Attack-State Estimation"). Intentionally coarse-grained.
/// </summary>
public enum AttackState
{
    Benign = 0,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
}

/// <summary>
/// Graduated automated-response level (doc §14, response-policy table).
/// Ordered from least to most disruptive; the policy engine only ever escalates
/// one rung at a time unless a rule explicitly allows a jump.
/// </summary>
public enum ResponseLevel
{
    Observe = 0,
    Enrich = 1,
    Restrict = 2,
    Contain = 3,
    EnterpriseResponse = 4,
}
