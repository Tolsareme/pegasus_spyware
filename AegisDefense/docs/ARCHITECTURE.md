# Architecture

This document explains how Aegis Autonomous Defense is put together, the technology
choices behind it, and — just as importantly — what the research document describes that
is **not** implemented yet.

## Layered view

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Aegis.Gui  (WPF, net48)                                                │
│  Dashboard / Alerts / Events / Policy & Autonomy / Deception /          │
│  Vulnerabilities / Approvals                                            │
└───────────────────────────────┬─────────────────────────────────────────┘
                                 │ named pipe, NDJSON, Administrators-only ACL
                                 │ (Aegis.Ipc)
┌───────────────────────────────▼─────────────────────────────────────────┐
│  Aegis.Service  (Windows Service, net48)                                │
│  ┌─────────────┐   ┌────────────────────────────────────────────────┐  │
│  │ Aegis.Sensor│──▶│ DefenseEngine                                   │  │
│  │ collectors  │   │  Deception → Store → Graph → Features → Rules  │  │
│  └─────────────┘   │  → AttackState → HostRisk → ResponsePolicy     │  │
│                     └───────────────────┬────────────────────────────┘ │
│                                          │                              │
│                     ┌────────────────────▼──────────┐                  │
│                     │ Aegis.ResponseActions          │                  │
│                     │ netsh / sc.exe / Process.Kill   │                 │
│                     └────────────────────────────────┘                  │
└───────────────────────────────┬─────────────────────────────────────────┘
                                 │
                     ┌───────────▼───────────┐
                     │ Aegis.Data (SQLite)    │
                     │ events/alerts/policy/  │
                     │ vulns/decoys/approvals │
                     └────────────────────────┘

  Aegis.Core (netstandard2.0 + net8.0, zero OS dependency, unit-tested)
  models · rule engine · scoring · graph · attack-state estimation ·
  response policy engine · deception logic · vulnerability prioritization
```

`Aegis.Core` is deliberately the only assembly every other project depends on for
*decisions*. `Aegis.Sensor` and `Aegis.ResponseActions` are the only assemblies that touch
the OS. This means the entire detection/scoring/policy logic is unit-testable on any
machine (63 tests, `dotnet test`, verified during development on Linux) even though the
product only *runs* on Windows.

## Technology choices

**.NET Framework 4.8 for OS-facing projects (`Aegis.Sensor`, `Aegis.ResponseActions`,
`Aegis.Service`, `Aegis.Gui`), not .NET 8.** This was the deciding constraint: the task
requires running on old *and* new Windows machines and Windows Server. .NET 8 only
supports Windows 10 1607+ / Server 2012 R2+ — it drops Windows 7/8/8.1 entirely. .NET
Framework 4.8 is preinstalled on Windows 10 1903+/11/Server 2016+ and is an in-place,
no-reboot-required update on Windows 7 SP1/8.1/Server 2008 R2 SP1+. It is the only .NET
runtime that actually spans the whole requested range.

**`netstandard2.0` (plus `net8.0` for fast local testing) for `Aegis.Core`/`Aegis.Data`/
`Aegis.Ipc`.** netstandard2.0 is the binary contract both net48 and net8.0 can consume, so
the same compiled decision logic runs inside the net48 service and can be exercised by a
fast, modern test suite. A few BCL gaps on netstandard2.0/net48 (`Math.Clamp`,
`Enumerable.MaxBy`, generic `Enum.Parse<T>`, C# 11 `required`/records' `init` accessor
support) are bridged by small compile-time-only shims in `Aegis.Core/Compat/` — the same
technique the `PolySharp` package automates, hand-rolled here to avoid an extra dependency
for four marker types.

**SQLite (`Microsoft.Data.Sqlite`), not a client/server database.** The sensor/service has
to run unattended on isolated endpoints and small servers with zero external
infrastructure. SQLite needs nothing installed, works identically on Windows 7 through
Server 2025, and is fast enough for this workload (WAL mode, indexed by host+timestamp).

**Named pipes (`System.IO.Pipes`), not gRPC/a message bus**, for GUI↔Service IPC, despite
doc §20 suggesting gRPC for the (inter-host) event transport. This is a *local*,
same-machine, admin-only control channel — named pipes need no additional runtime, no
port, no TLS certificate management, and their ACL (`PipeSecurity`, restricted to
`BUILTIN\Administrators` + `LocalSystem`) already gives the access control gRPC would need
extra plumbing for. The wire format (NDJSON envelopes, `Aegis.Ipc.IpcEnvelope`) was kept
simple and human-readable on purpose, for auditability.

**RSA-SHA256 signed policies over the classic XML key-interchange format, not PEM.**
`RSA.ImportFromPem`/`ExportRSAPublicKeyPem` don't exist on .NET Framework 4.8 — they're
.NET 5+ only. The XML format (`RSA.ToXmlString`/`FromXmlString` via
`RSACryptoServiceProvider`) has been stable since .NET Framework 1.1 and works identically
everywhere this solution runs. `PolicySignature` (in `Aegis.Core`) itself is
format-agnostic — it signs/verifies whatever `RSA` object it's given — so this is purely a
key-*loading* detail, isolated to `Aegis.Gui.Services.PolicySigningKeyManager` and
`Aegis.Service.PolicyTrustStore`.

**WMI + classic Security event log polling/subscriptions instead of the C++/ETW sensor
the doc's MVP section describes.** `ManagementEventWatcher` on `Win32_ProcessStartTrace`,
`Win32_Service` instance events, and `EventLogWatcher` on the Security log and PowerShell
operational log are all *push-based* (no busy-polling) and have shipped unchanged since
Windows XP/Vista — meaning zero extra setup on the oldest supported OS, at the cost of
slightly higher overhead than a native ETW consumer. `NetworkConnectionCollector` and
`RegistryPersistenceCollector` do poll (5s and 30s intervals respectively) because there is
no lightweight push API for TCP-table/registry changes without ETW or a kernel driver.
**ETW is the documented upgrade path** (doc §19: "where useful") once this baseline sensor
is proven — see "Not yet implemented" below.

## Response policy & safety

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
service, increase telemetry, request credential revocation). There is intentionally no
"run arbitrary command" method anywhere — the policy engine's decision is the *only* path
to a privileged effect (doc §29).

## Extensibility seams

- **`IProcessBaseline`** — swap `InMemoryProcessBaseline` for a trained/periodically
  refreshed model (WP2).
- **`HostRiskCalculator.Compute(... mlAnomalyScore, vulnerabilityExposureScore,
  attackSequenceScore ...)`** — three externally-supplied `[0,1]` signals are where a real
  ML anomaly model, external vulnerability scanner, and/or learned sequence model (WP4)
  plug in without touching the fusion logic.
- **`IResponseExecutor`** — implement against a different OS or a fleet-coordination
  backend for true "Enterprise response" (multi-host) instead of `WindowsResponseExecutor`'s
  single-host scope.
- **`ITelemetryCollector`** — add an ETW-based collector (e.g. via
  `Microsoft.Diagnostics.Tracing.TraceEvent`) alongside or instead of the WMI/EventLog ones
  without touching `DefenseEngine`.
- **`IAegisLogger`** — swap `RollingFileLogger` for Windows Event Log, a SIEM forwarder, etc.

## Not yet implemented

Being explicit about this matters more than pretending otherwise:

- **Learned sequence/ML models (WP4)** — the rule engine (deterministic, doc §8) and a
  simple frequency-based process baseline are implemented; a trained anomaly/sequence model
  is a seam (`mlAnomalyScore`), not a shipped model.
- **C++/ETW low-level sensor** — the MVP sensor uses WMI/EventLog instead (see above); ETW
  is the documented next step.
- **Cross-host correlation / "Enterprise response"** — each `Aegis.Service` instance is
  self-contained per doc §19's per-endpoint diagram; there is no fleet-wide event bus or
  central console in this repo yet, so `FeatureSnapshot.CrossHostSimilarHostCount` is always
  0 and `ResponseLevel.EnterpriseResponse` behaves the same as `Contain` locally.
- **Credential revocation** — `WindowsResponseExecutor.RevokeCredentialAsync` deliberately
  returns `Success=false`; it requires an organization-specific AD/Entra ID integration
  doc §17 calls for, which cannot be assumed generically.
- **Ringed patch rollout orchestration (doc §18, steps 5-10)** — vulnerability
  *prioritization* and mitigation *suggestions* are implemented; canary deployment/rollback
  automation is not.
- **Evaluation harness (WP10) / experimental metrics (doc §22)** — these require an
  isolated attack-range and labeled dataset program, out of scope for a code deliverable.
- **Runtime behavior of the four Windows-only projects is unverified in this environment.**
  `dotnet build AegisDefense.sln` — all eight projects, including the WPF `Aegis.Gui` —
  compiles cleanly with zero errors/warnings, which was confirmed during development. What
  wasn't (and can't be, without a Windows machine) verified here is *running* any of it: no
  WMI event actually fired, no named pipe actually connected, no `netsh` rule was actually
  applied. Treat a real Windows install (`docs/OPERATIONS.md`) as the next required
  verification step, and add it as a CI stage.

## Repository context

This code lives in a repository that also contains decompiled Pegasus spyware samples used
for security research/analysis. `AegisDefense/` is unrelated defensive tooling — an
endpoint/server detection-and-response platform for systems you own or are authorized to
protect — and does not use, reference, or repackage anything from the spyware samples.
