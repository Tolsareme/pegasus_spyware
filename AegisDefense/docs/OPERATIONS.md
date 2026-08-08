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
  store; it is never automatically pruned by this MVP.

## Deploying decoys

Use the console's **Deception** tab, or send a `RegisterDecoy` IPC request, to register a
`DecoyResourceDefinition`. Remember: the decoy's *location* (a file path, share, or service
identity name) needs to actually exist/be created on the host for the corresponding
collector to observe access to it — this MVP registers the *definition* (so the engine
knows to reclassify access to that location as a canary hit) but does not yet create the
decoy artifact on disk for you. Creating the file/share/identity itself is an operational
step; automating that is a natural next increment (`Aegis.Deception`-style helper) once the
detection side is validated in your environment.
