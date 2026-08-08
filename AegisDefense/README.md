# Aegis Autonomous Defense

An implementation of the research method in
[`docs/Autonomous_AI_Cyber_Defense_Method_Windows.md`](docs/Autonomous_AI_Cyber_Defense_Method_Windows.md):
behavioral detection, attack-state estimation, deception, predictive defense, and
policy-bounded automated response for Windows endpoints, Windows Server, and mixed old/new
Windows fleets — with a WPF desktop console for alerts, statistics, event management, and
full control over which parts run autonomously, plus (v2) real cross-host correlation via
a central Fleet Hub, RBAC, tamper-evident storage, SIEM export, and more. See
[`docs/CHANGELOG.md`](docs/CHANGELOG.md) for the v1 → v2 delta.

This is **defensive** software: it detects and contains attacks against systems you own or
are authorized to protect. It does not attribute attacks to a specific AI model, and every
automated action is bounded, reversible where possible, logged, and gated by a signed,
operator-controlled policy (see [§14/§29 of the design doc](docs/Autonomous_AI_Cyber_Defense_Method_Windows.md)).

## What's here

| Component | Project | Runs on |
|---|---|---|
| Detection/scoring/policy engine (portable) | `Aegis.Core` | anywhere (netstandard2.0 + net8.0) |
| SQLite storage | `Aegis.Data` | anywhere (netstandard2.0 + net8.0) |
| Named-pipe IPC contracts + transport | `Aegis.Ipc` | anywhere (netstandard2.0 + net8.0) |
| Telemetry collectors (ETW preferred, WMI/EventLog fallback) | `Aegis.Sensor` | Windows (net48) |
| Containment/mitigation actions incl. AD credential revocation | `Aegis.ResponseActions` | Windows (net48) |
| Windows Service host | `Aegis.Service` | Windows (net48) |
| **Desktop console (GUI)** | `Aegis.Gui` | Windows (net48 + WPF) |
| **Central Fleet Hub** (v2 - cross-host correlation) | `Aegis.FleetHub` | anywhere (net8.0, ASP.NET Core minimal API) |
| Unit + integration tests | `Aegis.Tests` | anywhere (net8.0, xUnit) |

See **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** for the full design, how it maps to
the research document, and why each technology was chosen. See
**[docs/OPERATIONS.md](docs/OPERATIONS.md)** for build/install/provisioning steps, and
**[docs/WINDOWS_VALIDATION_CHECKLIST.md](docs/WINDOWS_VALIDATION_CHECKLIST.md)** for the
concrete checklist of what still needs to be verified on a real Windows host - this was
developed and tested in a Linux sandbox (compiler + portable test suite only), so nothing
Windows-only has run yet.

## Quick start (development)

```powershell
# Build everything (Windows, with the Windows Desktop workload installed for the GUI)
dotnet build AegisDefense.sln -c Release

# Run the service in console mode (elevated), no installation needed
.\src\Aegis.Service\bin\Release\net48\AegisDefenseService.exe --console

# In another elevated window, run the console
.\src\Aegis.Gui\bin\Release\net48\AegisDefenseConsole.exe
```

For a real deployment (Windows Service + policy signing key provisioning + optional Fleet
Hub/RBAC/SIEM), see `scripts/install-service.ps1` and `docs/OPERATIONS.md`. For a packaged
install, see `installer/` (WiX MSI).

## Running the tests

```bash
dotnet test tests/Aegis.Tests/Aegis.Tests.csproj
```

Every project in `AegisDefense.sln`, including the WPF `Aegis.Gui` console, builds with
zero errors/warnings via `dotnet build AegisDefense.sln` — verified during development. The
portable projects (`Aegis.Core`, `Aegis.Data`, `Aegis.Ipc`, `Aegis.FleetHub`) additionally
run their full xUnit suite (103 tests, including real HTTP integration tests against the
Fleet Hub) on any OS with the .NET 8 SDK. Compiling is not the same as running, though:
`Aegis.Sensor`/`Aegis.ResponseActions`/`Aegis.Service`/`Aegis.Gui` all call Windows-only
APIs (WMI, ETW, the Security event log, named-pipe ACLs, `netsh`/`sc.exe`, Active
Directory, DPAPI) that only *execute* correctly on a real Windows host — exercise them
there before a production rollout. A GitHub Actions workflow
(`.github/workflows/aegis-defense-ci.yml`) automates this build/test matrix (Linux job for
fast feedback + a required Windows job) for every change.

## Safety notes

- Auto-containment is **off by default**. Enabling it, and every high-impact action
  (isolation, service disable, credential revocation), goes through a signed-policy gate —
  see `docs/ARCHITECTURE.md#response-policy-rbac--safety`.
- The AutonomyScore (machine-speed-adaptation signal) can never by itself trigger a
  high-impact response — this is enforced in code
  (`Aegis.Core/Policy/ResponsePolicyEngine.cs`), not just documented.
- RBAC (v2) is enforced server-side: a caller mapped to the Analyst role is refused every
  mutating control-channel request, not just hidden in the GUI — see
  `Aegis.Service/IpcRequestHandler.cs`.
- The event store is hash-chained (v2) so silent tampering or deletion of stored telemetry
  is detectable via the console's "Verify Event Chain" action — see
  `Aegis.Core/Integrity/EventChainSigner.cs`.
- All testing of detection/response behavior should occur on systems you own or are
  explicitly authorized to test, ideally in an isolated lab — see doc §29 "Defensive Scope
  and Governance".
