# Changelog

## v2.3 - enterprise remediation actions + interactive notifications

Implements the operator ask: "a setting that lets detection either just create an alert
(as today), or also pop an actionable notification (Remove / Quarantine / Ignore), plus an
automatic mode that removes the threat and rolls back what it did - and in every case,
notifications for what the attack did and what was done about it (suspended process,
blocked network connection, etc.)."

**Scoping note, stated up front:** "rollback" here means bounded, reversible,
evidence-scoped actions - quarantine (move + inert, restorable), not delete; disable
(restorable), not uninstall, for services/scheduled tasks; registry values are backed up
before being deleted so they can be restored. It is not a system-image time machine, and it
never fires on `AutonomyScore` alone - automatic remediation is a layer on top of the
existing `AutoContainmentEnabled` gate and the `IsAutonomyDominated` safety check, never a
way around them.

- **Response actions** (`Aegis.ResponseActions.WindowsResponseExecutor`): quarantine/restore
  a file (`%ProgramData%\AegisDefense\quarantine`, with a JSON sidecar recording the
  original path so it can be put back exactly where it came from); disable/restore a
  persistence artifact - service (start-type backed up first), scheduled task
  (`schtasks /Change /DISABLE`), or registry run-key value (value + kind backed up before
  delete) - dispatched from the same `ObjectId` identity each collector already produces, so
  "the artifact this alert's evidence points at" and "the artifact remediation acts on" are
  guaranteed to be the same thing.
- **Manual alert actions**: new `ExecuteAlertAction` IPC message and `AlertActionKind`
  (`Remove` / `Quarantine` / `Ignore`), wired through `DefenseEngine.ExecuteAlertActionAsync`.
  `Remove` walks the alert's own evidence events and terminates the process, quarantines its
  file, disables any persistence artifact, and blocks the flagged destination IP - never a
  general host-wide cleanup pass. `Quarantine` only touches the file(s). `Ignore` marks the
  alert `FalsePositive`. Every action taken is appended to the alert's own
  `EvidenceSummary` (prefixed `[ACTION] `) so the audit trail and the GUI's notification
  feed can tell a finding line from a remediation line without guessing at wording.
- **Automatic remediation mode** (`EngineToggles.AutoRemediationEnabled`, opt-in, off by
  default): when a decision already resolved to `Contain`/`EnterpriseResponse` and
  auto-containment already ran, this additionally runs the same evidence-scoped remediation
  as the manual `Remove` action - "remove the threat and restore normal operation"
  automatically, gated behind the same safety checks as every other auto-executed action.
- **Interactive notifications**: `NotificationSettings.Mode` (`AlertsOnly` /
  `InteractiveAction`, console-side only - has no effect on detection or on what the
  service does). In `InteractiveAction` mode, a new alert pops a non-modal
  `ThreatNotificationWindow` toast (stacked bottom-right, like a notification center) with
  Remove/Quarantine/Ignore buttons wired to the same commands as the Alerts tab. Every
  response action (manual or automatic) also fires a tray balloon when
  `NotifyOnResponseActions` is on (default), so containment/remediation is never silent even
  when the console window isn't focused.
- GUI: Remove/Quarantine/Ignore buttons on the Alerts tab, an evidence/response-action panel
  under the alerts grid, and both new toggles on the Policy & Autonomy tab - all
  Administrator-gated client-side, and enforced server-side (`ExecuteAlertAction` is in
  `IpcRequestHandler`'s mutating-message set, which Analyst-role callers can't invoke).

Also includes a batch of real-Windows validation fixes found while hands-on testing v2.2 on
a physical machine (see `docs/WINDOWS_VALIDATION_CHECKLIST.md` for the full narrative):
SQLite native library load failure (`PlatformTarget=x64`), named-pipe RBAC role resolution
(`TokenImpersonationLevel.Impersonation` on the client, caller-identity resolution moved to
after the first pipe read), an Events-tab column-clipping fix, and a four-round
alert-flooding investigation whose real root cause was mixed UTC/local timezone offsets
breaking the string-based timestamp comparison behind alert deduplication - fixed alongside
sticky-correlation-field leakage in `HostBehaviorProfile` and a check-then-act race in the
new alert-coalescing logic that caused it.

Test suite: 103 → 112 (Windows validation fixes) → 117 (this feature), all passing. Full
solution (all 9 projects) builds with zero errors/warnings.

## v2.2 - patch rollout orchestrator wired end-to-end

- `PatchRolloutOrchestrator` (previously a standalone, tested-but-unwired component) is now
  driven by `DefenseEngine`, persisted via a new `Aegis.Data.PatchPlanRepository`, exposed
  over the control pipe (`CreatePatchPlan`/`ApplyPatchMitigation`/`BeginPatchCanaryTesting`/
  `RecordPatchCanaryHealthCheck`/`BeginPatchRingDeployment`/`RecordPatchRingHealthCheck`/
  `ClosePatchMitigation`/`RollbackPatchPlan`), and controllable from a new **Patching** tab
  in the GUI. Still missing: automatic plan creation from a vulnerability finding, and a
  real automated health-check probe (health checks are an explicit operator judgment call
  today) - see `docs/ARCHITECTURE.md`.
- Fixed a real bug found while wiring persistence: `PatchRolloutPlan.History` (a get-only
  `List<T>` property) silently deserialized to an empty list through `Aegis.Data`'s JSON
  round-trip when the containing type also has `required` members - the audit trail would
  have looked empty on every read from storage. Caught by a repository round-trip test
  before it shipped; fixed by giving `History` an internal setter + `[JsonInclude]`, same as
  the plan's other orchestrator-only-mutable fields.

Test suite: 101 → 103 tests, all passing.

## v2.1 - decoy materialization + security-review fixes

- Registering a `File`/`Directory`/`Share` decoy now actually creates the artifact on disk
  (`Aegis.ResponseActions.WindowsDecoyMaterializer`) and best-effort sets a SACL audit rule
  so touching it fires Security-log event 4663, which `SecurityEventLogCollector` now
  understands - closing the v1/v2 gap where only the decoy *definition* was registered.
  `ServiceIdentity`/`HoneyCredential`/`Api` decoys are deliberately not auto-provisioned.
- Ran the security-review skill against the full codebase and fixed everything actionable
  without a Windows environment: signed-policy replay (a validly-signed but stale policy
  could previously be replayed to silently downgrade auto-containment - `SetPolicyAsync` now
  requires a strictly newer version), netsh/sc.exe argument-injection hardening
  (`ArgumentEscaping.Quote`), a fail-open/fail-closed contract bug in `AegisPipeServer` (a
  throwing `identifyCaller` resolver could previously be indistinguishable from "no RBAC
  configured," which is fully trusted), and a `WhoAmI` correctness bug (it echoed the role
  string instead of the actual Windows identity).

Test suite: 98 → 101 tests, all passing.

## v2

Implements the v2 roadmap that was proposed after v1 shipped, in priority order:

**Detection intelligence**
- Real online statistical anomaly engine (`Aegis.Core.Anomaly`) — an unsupervised,
  per-host/per-feature model that can now independently raise an alert with zero rule
  findings, not just add a score behind the rule engine.
- ETW kernel telemetry collector (`Microsoft.Diagnostics.Tracing.TraceEvent`), preferred
  over the WMI/EventLog baseline when it can run, with automatic fallback and no
  double-reporting.
- Fleet Hub (`Aegis.FleetHub`, new) + real cross-host correlation: `AutonomyScore`'s
  cross-host-coordination term is no longer always 0.

**Response & orchestration**
- Real Active Directory credential revocation (disable + expire password, reversible).
- Ringed patch-rollout state machine (`Aegis.Core.Patching`) implementing doc §18's
  ten-step workflow with automatic rollback on failed health checks — not yet wired to a
  real patch executor or the GUI (see `docs/ARCHITECTURE.md`).

**Trust & operability**
- Tamper-evident event hash-chaining (`Aegis.Core.Integrity`) with a one-click GUI
  verification action.
- Event retention/rollup (policy-configurable, alerts/audit never pruned).
- CEF-over-syslog SIEM export.
- RBAC (Administrator/Analyst) enforced server-side over the control pipe.

**GUI**
- Host inventory tab, attack-graph visualization tab, dashboard trend sparklines, system
  tray with critical-alert notifications.

**Packaging**
- WiX MSI installer definition (unverified in this dev environment - see
  `docs/ARCHITECTURE.md`).
- GitHub Actions CI workflow (`.github/workflows/aegis-defense-ci.yml`).

Also fixed two latent bugs found while building the above: `AegisDatabase.OpenInMemoryForTests()`
used a fixed shared-cache database name, so different test classes could silently share
state; and the Fleet Hub's API-key check treated an empty (not just null) configuration
value as "configured," which would have shipped a default deployment that silently required
an empty header value instead of refusing to start.

Test suite: 63 → 98 tests, all passing. Full solution (all 9 projects as of v2, including
the WPF GUI and the new Fleet Hub) still builds with zero errors/warnings.

## v1

Initial implementation of the MVP scope from
`docs/Autonomous_AI_Cyber_Defense_Method_Windows.md` §24: behavioral rule engine (16
rules), AutonomyScore + composite HostRisk scoring, attack-state graph and estimator with
next-objective prediction, deception/canary handling, vulnerability prioritization, and a
signed-policy-gated response engine, wired into a Windows Service (WMI/EventLog telemetry,
SQLite storage, named-pipe control channel) and a WPF desktop console (alerts, statistics,
event management, policy/autonomy controls). 63 tests, all 8 projects building clean
including the WPF GUI.
