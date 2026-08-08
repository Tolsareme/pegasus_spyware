# Operations Guide

## Building

Requires the .NET 8 SDK. Building `Aegis.Gui` additionally requires the ".NET desktop
development" workload (Visual Studio) or the `Microsoft.NET.Sdk.WindowsDesktop` components,
and a Windows machine — WPF cannot be built on Linux/macOS.

```powershell
dotnet restore AegisDefense.sln
dotnet build AegisDefense.sln -c Release
```

To build/test only the cross-platform pieces (useful in CI on any OS, or for quick
iteration on the detection/scoring logic):

```bash
dotnet build src/Aegis.Core/Aegis.Core.csproj -c Release
dotnet build src/Aegis.Data/Aegis.Data.csproj -c Release
dotnet build src/Aegis.Ipc/Aegis.Ipc.csproj -c Release
dotnet test tests/Aegis.Tests/Aegis.Tests.csproj -c Release
```

`Aegis.Sensor`, `Aegis.ResponseActions`, and `Aegis.Service` (net48, no WPF) will also
build on Linux/macOS via `Microsoft.NETFramework.ReferenceAssemblies` (already referenced
conditionally in their `.csproj` files) — useful for catching compile errors in CI before a
Windows-only build stage runs the full solution. Their *runtime* behavior can only be
exercised on Windows.

## First-time deployment on one host

1. **Build in Release** (see above) on a Windows machine with the full SDK + WPF workload.
2. **Install the service:**
   ```powershell
   cd scripts
   .\install-service.ps1
   ```
   This registers `AegisDefenseService` (LocalSystem, delayed-auto-start) via `sc.exe` and
   creates `%ProgramData%\AegisDefense\{data,logs,keys}`. It does **not** start the service
   yet.
3. **Provision a policy-signing trust key** (do this once per operator/organization, not
   per host):
   - Run `Aegis.Gui\bin\Release\net48\AegisDefenseConsole.exe` (elevated) on the
     administrator's workstation, go to **Policy & Autonomy**, click **Generate New Signing
     Key**, then **Export Public Key for Service Install**. This writes
     `policy-trusted-public.xml` to the desktop.
     *(Headless alternative: `scripts\New-PolicySigningKey.ps1 -PublicKeyOutputPath
     .\policy-trusted-public.xml`.)*
   - Copy that file to **every service host** as
     `%ProgramData%\AegisDefense\keys\policy-trusted-public.xml`.
   - **Keep the private key safe.** It lives DPAPI-protected at
     `%AppData%\AegisDefense\policy-signing-key.protected` under the operator's Windows
     account — it cannot be used from a different account or a different machine's DPAPI
     master key, so treat "who can run the console as this Windows user" as "who can sign
     policy for your fleet."
4. **Start the service:**
   ```powershell
   Start-Service AegisDefenseService
   ```
   The service works immediately with safe built-in defaults (all detection engines on,
   auto-containment **off**, every high-impact action requires approval) even before step 3
   — step 3 is only required to *change* that policy from the console.
5. **Run the console** on an administrator's machine (it can be the same machine as the
   service, or any machine that can reach `\\<host>\pipe\AegisDefense.Control.v1` — note:
   the shipped pipe is local-only by design; remote GUI access would require an explicit,
   separate design decision, not just a hostname change) to see alerts, statistics, and
   events, and to manage policy/deception/approvals.

## Updating policy

Edit the toggles/thresholds in the console's **Policy & Autonomy** tab, then click **Save &
Apply Policy** — this signs the policy with the operator's key and pushes it to the service,
which verifies the signature against its installed trust key before applying anything. A
policy that fails verification is rejected and logged (`audit-*.log`); the service keeps
running under whatever policy was last successfully verified.

## Uninstalling

```powershell
cd scripts
.\uninstall-service.ps1            # keeps data/logs
.\uninstall-service.ps1 -PurgeData # also deletes %ProgramData%\AegisDefense
```

## Logs and audit trail

- `%ProgramData%\AegisDefense\logs\aegis-YYYY-MM-DD.log` — general leveled logs.
- `%ProgramData%\AegisDefense\logs\audit-YYYY-MM-DD.log` — every automated/approved
  decision (isolate, restrict, disable service, policy change, approval/rejection), never
  filtered by log level (doc §29: "log every automated decision").
- `%ProgramData%\AegisDefense\data\aegis.db` — SQLite database (events, alerts, policy
  history, vulnerabilities, decoys, approvals). Back this up like any forensic evidence
  store. Raw events are subject to the configurable retention policy below; alerts and the
  audit trail itself are **never** pruned.

## Deploying decoys

Use the console's **Deception** tab, or send a `RegisterDecoy` IPC request, to register a
`DecoyResourceDefinition`. Remember: the decoy's *location* (a file path, share, or service
identity name) needs to actually exist/be created on the host for the corresponding
collector to observe access to it — this MVP registers the *definition* (so the engine
knows to reclassify access to that location as a canary hit) but does not yet create the
decoy artifact on disk for you. Creating the file/share/identity itself is an operational
step; automating that is a natural next increment (`Aegis.Deception`-style helper) once the
detection side is validated in your environment.

---

## v2: Fleet Hub setup

The Fleet Hub is a small, off-endpoint ASP.NET Core service that aggregates heartbeats from
every `Aegis.Service` host and hands back a cross-host correlation snapshot (how many other
hosts are seeing similar activity right now), which feeds the `AutonomyScore`
cross-host-coordination term. It has no old-Windows constraint — run it anywhere the .NET 8
ASP.NET Core runtime is supported (a Windows Server VM, a Linux container, etc.), reachable
by every endpoint over HTTPS.

1. **Deploy the hub.**
   ```powershell
   dotnet publish src/Aegis.FleetHub/Aegis.FleetHub.csproj -c Release -o C:\AegisFleetHub
   ```
   Put it behind TLS (a reverse proxy such as IIS/ARR, nginx, or Caddy is the simplest way
   to get HTTPS in front of Kestrel) — the API key described below is a bearer credential,
   so it must never travel over plain HTTP outside a fully trusted network.
2. **Set the API key.** The shipped `appsettings.json` has `FleetHub:ApiKey` as an empty
   placeholder **on purpose** — the hub refuses to start with a blank or missing key rather
   than silently accepting unauthenticated reports. Set a real key via environment variable
   (preferred, keeps secrets out of the deployed file tree):
   ```powershell
   [Environment]::SetEnvironmentVariable("FleetHub__ApiKey", "<a long random string>", "Machine")
   ```
   or by editing `appsettings.Production.json` on the hub host. `/healthz` is the only
   endpoint exempt from the API-key check (for load-balancer/monitoring probes); every other
   endpoint requires the `X-Api-Key` header, compared in constant time.
3. **Point endpoints at the hub.** In the console's **Policy & Autonomy** tab (or by editing
   the signed policy directly), set `FleetSettings.Enabled = true`,
   `FleetSettings.HubUrl` to the hub's HTTPS base URL, `FleetSettings.ApiKey` to the same key
   from step 2, and `FleetSettings.ReportingIntervalSeconds` (default is a sane starting
   point; lower it only if you need faster cross-host correlation and can afford the extra
   traffic). Save & apply the policy — each service host then starts heartbeating to the hub
   on its own timer (`DefenseEngine.RunFleetReportingAsync`) and folding the returned
   correlation snapshot into its own `AutonomyScore` calculation.
4. **Verify.** `GET https://<hub>/healthz` should return 200 without a key. With the key,
   the hub's host-status endpoint should start listing every reporting endpoint within one
   reporting interval of the service starting.

If the hub is unreachable, a host's `IFleetClient` calls fail closed to a no-op — local
detection/response continues unaffected, it just loses the cross-host-coordination signal
until connectivity returns.

## v2: RBAC — provisioning the "AegisDefense Analysts" group

The control pipe now enforces two roles server-side (not just in the GUI):
**Administrator** (full control — policy changes, approvals, deception, containment
actions) and **Analyst** (read-only: dashboards, alerts, statistics, event/chain
verification, but every mutating request is refused by `Aegis.Service.IpcRequestHandler`
regardless of what the GUI sends).

- **Administrators** are resolved from local/domain **Administrators** group membership on
  the service host — no separate group to create.
- **Analysts** are resolved from a group named **`AegisDefense Analysts`**, which you create
  yourself (it does not exist by default, so nobody is silently granted analyst access):
  ```powershell
  # Local group (standalone host / workgroup):
  New-LocalGroup -Name "AegisDefense Analysts" -Description "Read-only Aegis Defense console access"
  Add-LocalGroupMember -Group "AegisDefense Analysts" -Member "CONTOSO\jdoe"

  # Or, in Active Directory, a domain security group with the same name, replicated/cached
  # locally the way your domain normally handles group membership for logon.
  ```
  The service resolves the connecting named-pipe client's Windows identity via
  `NamedPipeServerStream.RunAsClient` impersonation and checks membership against this group
  (see `Aegis.Service/WindowsCallerRoleResolver.cs`); if the group doesn't exist on a host,
  role resolution soft-fails (logs once, treats the caller as unauthenticated/no-access)
  rather than throwing, so a host you haven't provisioned the group on doesn't crash the
  pipe server.
- A caller in neither group gets `OperatorRole.Unknown` and is refused every request,
  mutating or not.
- The console's top bar shows the resolved role (**RoleDescription**) so an operator can
  immediately see whether they're connected as Administrator or Analyst, and mutating
  controls are disabled client-side too (`IsAdministrator` binding) as a UX nicety — the
  server-side check is what actually matters for safety.

## v2: SIEM export configuration

Alerts can be forwarded as CEF (Common Event Format) over syslog to any SIEM that accepts
CEF (Splunk, QRadar, Sentinel via a syslog collector, etc.). This is alert-only (not raw
telemetry) — configure it in the signed policy:

```
SiemForwardingSettings.Enabled = true
SiemForwardingSettings.Host    = "<your syslog/SIEM collector hostname or IP>"
SiemForwardingSettings.Port    = 514      # UDP by default
SiemForwardingSettings.UseTcp  = false    # set true for TCP syslog
SiemForwardingSettings.DeviceVendor = "AegisDefense"   # shows up in the CEF header
```

Apply via the console the same way as any other policy change (signed, verified, logged).
Once enabled, every alert the engine raises is also formatted as CEF
(`CefSyslogForwarder.FormatSyslogCef`) and sent best-effort over UDP or TCP syslog — a
forwarding failure is logged but never blocks or delays the local alert/response pipeline.
Test connectivity first with a generic `nc -ul 514` (or your collector's raw listener) on
the receiving end before wiring this to a production SIEM ingest pipeline.

## v2: Verifying the event chain

Every stored event is now HMAC-SHA256 hash-chained (`sequence`, `chain_hash`,
`prev_chain_hash` columns) using a per-host key that is generated on first run and
DPAPI-protected (`LocalMachine` scope) at
`%ProgramData%\AegisDefense\keys\event-chain-key.protected` — this makes silent tampering
or deletion of stored telemetry detectable, not impossible (an attacker with LocalSystem on
the box can still recompute the chain; the goal is to catch casual/remote tampering and
provide forensic assurance, not to defeat a fully compromised host).

To verify: in the console, click **Verify Event Chain** (Dashboard or Events tab). This
sends a `VerifyEventChain` IPC request (available to both Administrator and Analyst roles —
it's read-only) and reports:
- **Valid** — every link's hash matches its recomputed value and sequence numbers are
  contiguous.
- **Broken at sequence N** with a reason (`HashMismatch`, `PreviousHashMismatch`, or
  `SequenceGap`) — `SequenceGap`/`PreviousHashMismatch` specifically catch a *deleted* row
  (not just an edited one), because the verifier propagates its own recomputed previous hash
  forward through the chain rather than trusting each row's stored `prev_chain_hash`
  independently.

Run this after any incident where tampering is a concern, and consider scripting a periodic
check (e.g. a scheduled task calling into the pipe) if you want it enforced outside manual
console use.

## v2: Event retention policy

Raw telemetry events are the highest-volume table and the least forensically valuable once
they're old — the policy's `EventRetentionDays` (default 90) controls how long they're kept
before `DefenseEngine.RunRetentionAsync` prunes them on a background timer.
**Alerts and the audit log are never pruned by this mechanism**, regardless of
`EventRetentionDays` — only the underlying raw `events` table is affected, so your
alert/audit history and compliance trail are unaffected by tightening retention.

To change it, edit `EventRetentionDays` in the console's **Policy & Autonomy** tab (or the
signed policy directly) and save/apply as usual. Consider your evidentiary/compliance needs
before shortening it — once a batch of events is pruned it is gone from `aegis.db`; if you
need longer raw-event retention for compliance, forward events to your SIEM (see above,
though note SIEM export today only forwards *alerts*, not raw events) or back up `aegis.db`
before the retention window elapses.

## v2: Building and using the MSI installer

`installer/` contains a WiX v5 project (`AegisDefense.Installer.wixproj`) that packages the
published service + console into a single MSI. **This has not been validated by running it
end-to-end in this development environment** — WiX's own tooling declares non-Windows
behavior undefined, and this repo's dev sandbox is Linux, so treat the installer as
carefully-authored-but-unverified and test it on a real Windows machine before relying on it
for production rollout. The GitHub Actions workflow's `build-installer` job builds it on
`windows-latest` on every push as a best-effort check (`continue-on-error: true` — it
doesn't block the rest of CI, but its failure is visible).

To build locally on Windows (requires the WiX Toolset: `dotnet tool install --global wix
--version 5.0.2` then `wix extension add WixToolset.UI.wixext/5.0.2`):

```powershell
cd installer
.\build-installer.ps1
```

This publishes `Aegis.Service` and `Aegis.Gui` (`win-x64`, framework-dependent) and produces
`installer\bin\Release\*.msi`. The MSI still expects the same manual post-install steps as a
from-source deployment — policy-signing key provisioning (step 3 above), Fleet Hub policy
configuration, and RBAC group creation are operator actions, not something an MSI can safely
automate on your behalf (each is either a secret or a security-boundary decision that
shouldn't be baked into a package silently).
