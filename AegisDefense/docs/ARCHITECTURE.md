# Architecture

This document explains how Aegis Autonomous Defense is put together, the technology
choices behind it, and — just as importantly — what the research document describes that
is **not** implemented yet. See [`CHANGELOG.md`](CHANGELOG.md) for what shipped in v1 vs v2.

## Layered view

```
┌───────────────────────────────────────────────────────────────────────────┐
│  Aegis.Gui  (WPF, net48)                                                  │
│  Dashboard(+trends) / Alerts / Events / Hosts / Attack Graph /            │
│  Policy & Autonomy(RBAC-aware) / Deception / Vulnerabilities / Approvals  │
│  + system tray / critical-alert notifications                            │
└───────────────────────────────┬───────────────────────────────────────────┘
                                 │ named pipe, NDJSON, Administrators + Analysts ACL,
                                 │ per-connection RBAC (Aegis.Ipc)
┌───────────────────────────────▼───────────────────────────────────────────┐
│  Aegis.Service  (Windows Service, net48)                                  │
│  ┌──────────────┐   ┌─────────────────────────────────────────────────┐  │
│  │ Aegis.Sensor │──▶│ DefenseEngine                                    │  │
│  │ ETW (pref.)  │   │  Deception → Chain-sign → Store → Graph →       │  │
│  │ + WMI/EventLog│  │  Features → Rules → Anomaly(online stats) →     │  │
│  │  fallback    │   │  AttackState → HostRisk(+cross-host) →          │  │
│  └──────────────┘   │  ResponsePolicy → SIEM/Fleet forwarding          │  │
│                      └───────────┬─────────────────────┬───────────────┘  │
│                                  │                     │                  │
│                     ┌────────────▼──────────┐  ┌───────▼────────────┐    │
│                     │ Aegis.ResponseActions   │  │ HttpFleetClient /   │   │
│                     │ netsh / sc.exe /        │  │ CefSyslogForwarder  │   │
│                     │ Process.Kill / AD revoke │  │ (both best-effort) │   │
│                     └─────────────────────────┘  └──────────┬─────────┘   │
└───────────────────────────────┬────────────────────────────┼─────────────┘
                                 │                            │ HTTPS + API key
                     ┌───────────▼───────────┐    ┌───────────▼────────────┐
                     │ Aegis.Data (SQLite)    │    │ Aegis.FleetHub (net8.0) │
                     │ events(+chain)/alerts/ │    │ cross-host correlation, │
                     │ policy/vulns/decoys/   │    │ fleet roster - central, │
                     │ approvals              │    │ org-controlled infra    │
                     └────────────────────────┘    └─────────────────────────┘

  Aegis.Core (netstandard2.0 + net8.0, zero OS dependency, unit-tested)
  models · rule engine · online anomaly model · scoring · graph ·
  attack-state estimation · response/RBAC policy · deception · vulnerability
  prioritization · event hash-chaining · SIEM formatting · fleet aggregation ·
  patch-rollout state machine
```

`Aegis.Core` is deliberately the only assembly every other project depends on for
*decisions*. `Aegis.Sensor` and `Aegis.ResponseActions` are the only assemblies that touch
the local OS; `Aegis.FleetHub` is the only one that runs off-endpoint. This means the
entire detection/scoring/policy logic is unit-testable on any machine (98 tests,
`dotnet test`, verified during development on Linux, including real HTTP integration tests
against the Fleet Hub) even though the endpoint product only *runs* on Windows.

## Technology choices

**.NET Framework 4.8 for OS-facing endpoint projects (`Aegis.Sensor`,
`Aegis.ResponseActions`, `Aegis.Service`, `Aegis.Gui`), not .NET 8.** This was the deciding
constraint: the task requires running on old *and* new Windows machines and Windows
Server. .NET 8 only supports Windows 10 1607+ / Server 2012 R2+ — it drops Windows
7/8/8.1 entirely. .NET Framework 4.8 is preinstalled on Windows 10 1903+/11/Server 2016+
and is an in-place, no-reboot-required update on Windows 7 SP1/8.1/Server 2008 R2 SP1+. It
is the only .NET runtime that actually spans the whole requested range. **`Aegis.FleetHub`
(v2) is the one exception** — it's a central service that runs on infrastructure the
organization controls, not on a protected endpoint, so it targets net8.0 directly with no
compatibility constraint.

**`netstandard2.0` (plus `net8.0` for fast local testing) for `Aegis.Core`/`Aegis.Data`/
`Aegis.Ipc`.** netstandard2.0 is the binary contract both net48 and net8.0 can consume, so
the same compiled decision logic runs inside the net48 service and can be exercised by a
fast, modern test suite. A few BCL gaps on netstandard2.0/net48 (`Math.Clamp`,
`Enumerable.MaxBy`, generic `Enum.Parse<T>`, C# 11 `required`/records' `init` accessor
support) are bridged by small compile-time-only shims in `Aegis.Core/Compat/` — the same
technique the `PolySharp` package automates, hand-rolled here to avoid an extra dependency
for four marker types.

**SQLite (`Microsoft.Data.Sqlite`), not a client/server database**, for local endpoint
storage. The sensor/service has to run unattended on isolated endpoints and small servers
with zero external infrastructure. SQLite needs nothing installed, works identically on
Windows 7 through Server 2025, and is fast enough for this workload (WAL mode, indexed by
host+timestamp). `Aegis.FleetHub` (v2), by contrast, deliberately keeps *no* database at
all — it's an in-memory correlation cache (`FleetCorrelationStore`) that only needs to
remember the last ~15 minutes of activity; if it restarts, hosts just re-report.

**Named pipes (`System.IO.Pipes`), not gRPC/a message bus**, for GUI↔Service IPC, despite
doc §20 suggesting gRPC for the (inter-host) event transport. This is a *local*,
same-machine control channel — named pipes need no additional runtime, no port, no TLS
certificate management, and their ACL (`PipeSecurity`) already gives the access control
gRPC would need extra plumbing for. v2 extended the ACL to optionally include an
"AegisDefense Analysts" local group alongside Administrators/LocalSystem, with per-role
enforcement happening in `IpcRequestHandler` (see RBAC below) rather than at the ACL layer,
since Windows pipe ACLs have no concept of "read-only." **`Aegis.FleetHub` uses plain
HTTPS + an API key** instead, because that connection *does* cross the network/a
trust boundary between separate machines — the two transports were chosen for the
trust boundary each one actually crosses, not out of inconsistency.

**RSA-SHA256 signed policies over the classic XML key-interchange format, not PEM.**
`RSA.ImportFromPem`/`ExportRSAPublicKeyPem` don't exist on .NET Framework 4.8 — they're
.NET 5+ only. The XML format (`RSA.ToXmlString`/`FromXmlString` via
`RSACryptoServiceProvider`) has been stable since .NET Framework 1.1 and works identically
everywhere this solution runs. `PolicySignature` (in `Aegis.Core`) itself is
format-agnostic — it signs/verifies whatever `RSA` object it's given — so this is purely a
key-*loading* detail, isolated to `Aegis.Gui.Services.PolicySigningKeyManager` and
`Aegis.Service.PolicyTrustStore`.

**ETW preferred, WMI/classic Security event log as the always-available fallback (v2).**
`Aegis.Sensor.Collectors.EtwKernelCollector` (`Microsoft.Diagnostics.Tracing.TraceEvent`)
consumes the kernel Process/ImageLoad/NetworkTCPIP providers directly when the process is
elevated and can claim the single system-wide "NT Kernel Logger" session — lower overhead,
higher fidelity than the v1 baseline. `CollectorHost` tries it first and only starts the
WMI-based `ProcessTraceCollector`/`NetworkConnectionCollector` for whatever ETW didn't
actually cover, so the same activity is never double-reported. `ManagementEventWatcher` on
`Win32_Service`, and `EventLogWatcher` on the Security log and PowerShell operational log,
remain push-based (no busy-polling) and have shipped unchanged since Windows XP/Vista —
meaning the sensor still works with zero extra setup even where ETW can't run (non-elevated,
or another tool already owns the kernel session).

**A hand-rolled online statistical model, not a shipped trained model, for the "ML engine"
(v2).** `Aegis.Core.Anomaly.StatisticalAnomalyModel` uses Welford's streaming mean/variance
per feature per host, combined via RMS z-score into one explainable `[0,1]` score with named
top-contributing features. This needs no labeled dataset and starts learning the moment the
sensor runs — a real, functional unsupervised baseline, not a placeholder — but it's still a
diagonal model (per-feature independent), not a trained sequence/covariance model. It
implements `IAnomalyModel`, the seam a properly trained model (WP2/WP4) would replace.

**HMAC-SHA256 event hash-chaining, not a blockchain/Merkle structure (v2).**
`Aegis.Core.Integrity.EventChainSigner` links each stored event to the previous one via
`HMAC(key, sequence, prevHash, event)`; `EventChainVerifier` recomputes the chain forward
from genesis rather than trusting each row's own stored prev-hash column, so a deleted or
reordered record is exactly as detectable as an edited one. This is tamper-*evidence*, not
tamper-*proofing* — an attacker with both DB write access and the DPAPI-protected HMAC key
could forge a self-consistent alternate history. Raising the bar past that (e.g. periodic
external notarization of the chain head) is a further increment, not implemented.

**CEF-over-syslog for SIEM export, not a vendor-specific connector (v2).**
`Aegis.Core.Siem.CefSyslogForwarder` is the lowest-common-denominator format most SIEMs
(Splunk, Sentinel via syslog, Elastic via Logstash, ArcSight) already parse without a
custom integration, sent over UDP by default (fire-and-forget, matching typical syslog
listener deployment) with a TCP option. Forwarding is always best-effort — a SIEM outage
never blocks or slows down local detection/response.

## Response policy, RBAC & safety

`ResponsePolicyEngine.Decide` is the single chokepoint every automated action passes
through. Two safety properties are enforced in code, not just policy:

1. **AutonomyScore alone can never justify Contain/EnterpriseResponse.**
   `IsAutonomyDominated` checks whether every *other* HostRisk component is negligible; if
   so, the response is capped at Restrict regardless of the raw score, and the alert's
   evidence trail says why (doc §11).
2. **High-impact actions require either human approval or a pre-authorized, host-scoped
   emergency-playbook entry** — never a bare risk-score threshold (doc §14). The MVP's only
   playbook entry is `isolate-test-endpoint`, matching doc §24's MVP scope exactly.

`Aegis.Core.Response.IResponseExecutor` is a closed, enumerated set of actions (isolate,
release isolation, terminate one named process, apply/remove one firewall rule, disable one
service, increase telemetry, revoke/restore one credential, and — v2.3 — quarantine/restore
one file and disable/restore one persistence artifact). There is intentionally no
"run arbitrary command" method anywhere — the policy engine's decision is the *only* path
to a privileged effect (doc §29).

**Remediation & interactive notifications (v2.3).** `EngineToggles.AutoRemediationEnabled`
is a *second*, independent opt-in layered on top of `AutoContainmentEnabled`: even with both
on, remediation only ever runs after `ResponsePolicyEngine.Decide` has already resolved to
Contain/EnterpriseResponse through the two safety properties above, and it only ever acts on
artifacts named in *that alert's own evidence events* (`DefenseEngine.RemediateFromEvidenceAsync`
walks `Alert.EvidenceEventIds`, not a host-wide scan). The same code path backs the manual
`ExecuteAlertAction` IPC message (`AlertActionKind.Remove`/`Quarantine`/`Ignore`) that the
GUI's Alerts-tab buttons and the interactive notification popup both call — there is exactly
one remediation implementation, invoked either by an operator's click or by the automatic
pipeline, never two parallel ones to keep in sync. `NotificationSettings.Mode` is a
console-only setting (`Aegis.Gui.MainViewModel.DetectNotifications`) with no effect on
detection or on what the service does — it only decides whether the GUI pops an actionable
toast for a new alert on top of it appearing in the Alerts tab, and whether a response action
(manual or automatic) also raises a tray balloon.

**RBAC (v2)** adds a second gate in front of that chokepoint for *who may ask* for a
mutating action at all, independent of what the action is: `IpcRequestHandler` maps every
named-pipe connection to `OperatorRole.Administrator` or `.Analyst` via real Windows group
membership (`WindowsCallerRoleResolver`, using the pipe's built-in client impersonation),
and refuses every mutating message type outright for an Analyst - enforced server-side, not
just hidden in the GUI. A deployment that never provisions the "AegisDefense Analysts"
group is unaffected: the pipe's ACL (Administrators + LocalSystem only) remains the sole
gate, exactly as in v1.

## Extensibility seams

- **`IProcessBaseline`** — swap `InMemoryProcessBaseline` for a trained/periodically
  refreshed model (WP2).
- **`IAnomalyModel`** (v2) — swap `StatisticalAnomalyModel` for a trained/offline model
  (isolation forest, autoencoder, an ONNX Runtime-hosted network) without touching
  `DefenseEngine`'s fusion logic.
- **`HostRiskCalculator.Compute(... mlAnomalyScore, vulnerabilityExposureScore,
  attackSequenceScore ...)`** — three externally-supplied `[0,1]` signals are where a
  trained sequence model (WP4) plugs in without touching the fusion logic itself.
- **`IResponseExecutor`** / **`ICredentialRevoker`** (v2) — implement against a different
  OS, a different identity provider (Entra ID Graph instead of on-prem AD), or a
  fleet-coordination backend for true multi-host "Enterprise response" instead of
  `WindowsResponseExecutor`'s single-host scope.
- **`ITelemetryCollector`** — the seam `EtwKernelCollector` (v2) itself was added through;
  a future collector (e.g. a third-party EDR's telemetry export) plugs in the same way.
- **`IAegisLogger`** — swap `RollingFileLogger` for Windows Event Log, a different SIEM
  client, etc.
- **`ISiemForwarder`** (v2) — swap `CefSyslogForwarder` for a vendor SDK/HTTP-based
  forwarder without touching `DefenseEngine`'s alert pipeline.
- **`IFleetClient`** (v2) — swap `HttpFleetClient` for a different transport (gRPC, a
  message bus) to the Fleet Hub, or a different central aggregator entirely.
- **`PatchRolloutOrchestrator`** (v2) — the state machine is implemented, fully tested, and
  (v2.2) wired end-to-end through `DefenseEngine`/`Aegis.Data`/the control pipe/the GUI's
  Patching tab; see "Not yet implemented" below for what's still missing (a real patch
  executor, and automated health checks).
- **`IDecoyMaterializer`** (v2.1) — swap `WindowsDecoyMaterializer` for a different
  provisioning backend (e.g. one that also stands up honeytoken accounts through a real
  identity workflow) without touching `DefenseEngine`'s decoy registration path.

## Not yet implemented

Being explicit about this matters more than pretending otherwise:

- **Learned sequence/trained ML models (WP4)** — the rule engine (deterministic, doc §8)
  and the v2 online statistical anomaly model are both real and running; a *trained*
  offline model is still just a seam (`IAnomalyModel`, `mlAnomalyScore`), not a shipped
  model, because that requires a labeled fleet dataset this repo doesn't have.
- **`PatchRolloutOrchestrator` has no real patch executor or automated health checks behind
  it.** The state machine (doc §18's ten-step workflow, ring-by-ring health-check gating,
  automatic rollback on failure) is now wired end-to-end - `DefenseEngine` persists plans to
  `Aegis.Data` (`PatchPlanRepository`), exposes every transition over the control pipe
  (`CreatePatchPlan`/`ApplyPatchMitigation`/.../`RollbackPatchPlan`), and the GUI's
  **Patching** tab drives it - but two real integrations are still missing: (1) nothing
  automatically creates a `PatchRolloutPlan` from a `VulnerabilityPriority` finding yet, an
  operator creates one by hand; (2) `RecordCanaryHealthCheck`/`RecordRingHealthCheck` take
  whatever `HealthCheckResult` the caller supplies - today that's an operator's own
  Healthy/Unhealthy judgment call from the GUI, not a real automated
  application/service/boot/auth/network probe. Both are natural next increments once a real
  Windows Update Agent / WSUS / SCCM integration is in scope.
- **Fleet Hub uses a shared API key, not mutual TLS.** Fine for a first deployment behind
  a private network; a Hub reachable across an untrusted network should sit behind mTLS or
  a reverse proxy that terminates it — the shared-secret model doesn't rotate or scope per
  host.
- **No fleet-wide console UI.** `Aegis.Gui` talks to exactly one `Aegis.Service` over one
  local named pipe; it does not (yet) also query `Aegis.FleetHub` directly to show a
  multi-host dashboard. The Hub's `/api/v1/fleet/status` endpoint already returns what such
  a view would need.
- **`ServiceIdentity`/`HoneyCredential`/`Api` decoys aren't auto-provisioned** (v2.1's
  `WindowsDecoyMaterializer` handles `File`/`Directory`/`Share` decoys automatically; those
  three types would each mean creating a real Windows service, a real account, or standing
  up a real endpoint - a deliberate operator action, not an automated one). Register the
  definition and provision the artifact by hand for those types.
- **Evaluation harness (WP10) / experimental metrics (doc §22)** — these require an
  isolated attack-range and labeled dataset program, out of scope for a code deliverable.
- **The WiX installer (`installer/`) could not be verified at all in this environment** —
  more than "unverified," the WiX Toolset's own CLI explicitly declares non-Windows
  behavior undefined, and running it here on deliberately trivial input produced internal
  path-validation errors on inputs (like a plain relative directory name) that are valid
  per the WiX schema. The `.wxs` was authored carefully against documented WiX v5 syntax,
  but treat a real Windows build (`installer/build-installer.ps1`) as the first genuine
  verification, not a formality.
- **Runtime behavior of every Windows-only project was unverified in this environment** —
  now partially closed. `dotnet build AegisDefense.sln` compiles cleanly with zero
  errors/warnings for every project in the solution, including the WPF `Aegis.Gui`, and
  `Aegis.FleetHub` has real HTTP integration tests that pass; that much was always true. The
  baseline install, RBAC, and detection/alerting path have since been validated live on a
  real Windows 11 machine (see `docs/WINDOWS_VALIDATION_CHECKLIST.md` for the full
  bug-by-bug narrative — SQLite native-library loading, named-pipe RBAC impersonation, and a
  four-round alert-flooding investigation were all found and fixed this way, not by
  inspection). **The v2.3 remediation/notification feature (quarantine, persistence
  disable/restore, `ExecuteAlertAction`, the interactive notification popup, and
  `AutoRemediationEnabled`) has not yet been through that live-Windows pass** — it built
  clean and passed the cross-platform unit suite, but no quarantine actually moved a file,
  no service/task/registry value was actually disabled or restored, and no toast has
  actually popped on a real desktop. Treat that as the next required verification step
  before relying on it, same as every other Windows-only capability in this project.

## Repository context

This code lives in a repository that also contains decompiled Pegasus spyware samples used
for security research/analysis. `AegisDefense/` is unrelated defensive tooling — an
endpoint/server detection-and-response platform for systems you own or are authorized to
protect — and does not use, reference, or repackage anything from the spyware samples.
