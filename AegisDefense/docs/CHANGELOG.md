# Changelog

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
