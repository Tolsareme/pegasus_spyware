namespace Aegis.Core.Policy;

/// <summary>
/// Coarse RBAC for the control channel (v2). <c>Administrator</c> can do everything an
/// Administrator on the pipe's ACL could already do; <c>Analyst</c> is read-only (can view
/// alerts/events/statistics/graph/vulnerabilities but not change policy, acknowledge
/// alerts, or approve/reject actions); <c>Unknown</c> means the caller could not be
/// mapped to either role and is refused entirely. This is enforced authoritatively in
/// <c>Aegis.Service.IpcRequestHandler</c> server-side - anything the GUI does to grey out
/// buttons for a given role is a convenience, not the security boundary.
/// </summary>
public enum OperatorRole
{
    Unknown = 0,
    Analyst = 1,
    Administrator = 2,
}
