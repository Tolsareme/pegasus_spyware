# Changelog

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
