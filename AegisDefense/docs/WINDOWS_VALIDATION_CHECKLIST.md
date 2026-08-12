# Windows Validation Checklist

Everything in this repository has been verified the ways a Linux dev sandbox actually can:
every project compiles (including the WPF GUI, cross-compiled via
`Microsoft.NETFramework.ReferenceAssemblies`), the full portable test suite passes (103
tests as of v2.2), and every design decision is documented. **None of it has run on a real
Windows host.** This is the concrete, checkable list of what that first real run needs to
validate, organized so you can work through it host-by-host once a Windows environment
(ideally an isolated lab, per doc §29) is available. Nothing here is a known bug - it's the
boundary between "compiles and is logically correct" and "actually works," which only a real
Windows kernel, a real Security event log, a real named pipe with real impersonation, and
real `netsh`/`sc.exe` binaries can cross.

## How to use this

Check items off as you validate them on a real host. Where a check fails, that's a real bug
report with enough context (file, expected behavior) to act on immediately - please open an
issue or fix and note it here rather than silently working around it, since this file is the
source of truth for "have we actually run this yet."

## 1. Baseline: does it even run?

- [x] `dotnet build AegisDefense.sln -c Release` on Windows with the .NET 8 SDK + ".NET
      desktop development" workload. Confirms the WPF GUI actually links/runs, not just
      cross-compiles. **Verified.** Found and fixed along the way: a file-lock during
      restore (stale build-server process - `dotnet build-server shutdown` resolved it, not
      a code bug) and `Aegis.Service` needed `PlatformTarget=x64` pinned explicitly for
      `Microsoft.Data.Sqlite`'s native dependency to load reliably on classic .NET
      Framework (see the fix in `Aegis.Service.csproj`).
- [x] `AegisDefenseService.exe --console` starts without an unhandled exception, creates
      `%ProgramData%\AegisDefense\{data,logs,keys}`, and logs "Defense engine started."
      **Verified**, after the `PlatformTarget=x64` fix above.
- [x] `AegisDefenseConsole.exe` starts, connects to the console pipe, and the Dashboard tab
      populates within one refresh cycle (5s). **Verified**, after two real bug fixes found
      back-to-back on real Windows: (1) `AegisPipeClient` constructed its
      `NamedPipeClientStream` without `TokenImpersonationLevel.Impersonation`, which defaults
      to `.None` and made every v2 RBAC role-resolution attempt fail closed to `Unknown` -
      every request was refused with "Caller could not be mapped to an authorized role" even
      for a fully elevated Administrator (fixed in `Aegis.Ipc/AegisPipeClient.cs`); (2) after
      fixing (1), `AegisPipeServer` still resolved the caller's identity *before* reading
      anything from the pipe, which threw `"Unable to impersonate using a named pipe until
      data has been read from that pipe"` - a real Win32 `ImpersonateNamedPipeClient`
      constraint neither of us could have found without an actual named-pipe client
      connecting on real Windows. Fixed by moving resolution to after the first successful
      read (`AegisPipeServer.HandleClientAsync`). Both confirmed fixed: clean startup log,
      GUI shows "Administrator (full control)" with no error, Dashboard/Events populate.
- [ ] `scripts\install-service.ps1` actually registers and the service starts under
      `services.msc` / `Get-Service AegisDefenseService`.
- [ ] `scripts\uninstall-service.ps1` (with and without `-PurgeData`) actually removes it.

## 2. Telemetry collectors (Aegis.Sensor)

- [x] **ETW kernel collector** (`EtwKernelCollector`) actually starts when the service runs
      elevated (LocalSystem) - confirm via the service log that it's the active collector,
      not the WMI fallback. Test on both an old target (Windows 10 / Server 2016) and a new
      one (Windows 11 / Server 2025) since the doc's whole premise is spanning both.
      **Verified on Windows 11** (`DESKTOP-95MROPV`): log shows "ETW kernel session started
      (Process/ImageLoad/NetworkTCPIP)" and "WMI-based ProcessTrace/NetworkConnection
      collectors are not started, to avoid double-reporting" - real `ImageLoad` events (Chrome,
      system DLLs) and real `NetworkConnect` events (destination IP:port 53/DNS) flowed all
      the way through to the GUI's Events tab with sane field values. Also confirmed the
      collector's stale-session recovery path for free: a log line "An existing NT Kernel
      Logger session was found ... stopping it to reclaim the session" fired correctly after
      an earlier unclean shutdown during this same testing session. Still need: the same
      confirmation on an old target (Windows 10 / Server 2016) - not yet tested.
- [ ] **WMI fallback** actually engages when ETW can't start (e.g. run as a restricted, non-
      elevated account temporarily) and that `CollectorHost` doesn't double-report the same
      activity from both paths simultaneously.
- [ ] **Detection rule quality under real, live-fire activity** (in progress - two real bugs
      found and fixed, a third retest is still needed to confirm clean) - not originally a
      checklist
      line item, but real testing surfaced it, so recording it here. Ran an actual encoded
      PowerShell downloader cradle (`-enc` + `IEX (New-Object Net.WebClient).DownloadString(...)`
      against the harmless placeholder domain `example.com`) and checked the Alerts tab.
      **Found and fixed a severe bug**: `PersistenceAfterSuspiciousExecutionRule` fired 20+
      times for what should have been one detection - `HostBehaviorProfile` stored the
      "persistence shortly after suspicious execution" correlation as a sticky field that,
      once set, was included in *every* subsequent event's snapshot regardless of that event's
      type, so the rule kept re-firing on ordinary background activity (routine Windows
      service/task churn) for the rest of the host profile's in-memory lifetime. The same
      pattern affected two more rules (`CredentialAccessThenRemoteAuthRule`,
      `ReconToActionPivotRule`). Fixed and covered by 3 new regression tests.

      **Then found a second, more fundamental bug on retest**: a *different* rule
      (`HighActionFrequencyRule`, not touched by the fix above) immediately flooded the same
      way. Root cause was architectural, not rule-specific: `DefenseEngine.HandleEventAsync`
      created a brand-new `Alert` row, unconditionally, for every event that produced any rule
      finding - so any rule whose condition stays true across a sustained burst floods,
      regardless of whether its own feature-computation has a leak. Worse: `DecideAndActAsync`
      (the response decision/execution path) has no idempotency guard either - unconditionally
      creates a new `PendingApproval`, or unconditionally *re-executes* the actual response
      action if auto-containment is on and the level is auto-executable. A sustained burst with
      auto-containment enabled could have hammered `IsolateEndpointAsync`/`netsh` dozens of
      times for one incident. Auto-containment defaults off, so no real isolation happened
      here, but the exposure was real. Fixed with alert coalescing
      (`AlertRepository.FindRecentOpenAlertAsync` + merge-into-existing-alert logic in
      `HandleEventAsync`, gated so `DecideAndActAsync`/SIEM-forward only run for genuinely new
      alerts) - 4 new regression tests.

      **Retested and the flood was still there** - same rule, same pattern. Root cause of
      *that* was a check-then-act race: `CollectorHost` dispatches events to
      `HandleEventAsync` concurrently (fire-and-forget, no serialization), so during a real
      burst many events each checked "does an open alert exist?" before any of them had
      finished creating one. The first coalescing fix was logically correct for sequential
      processing but never accounted for the concurrency this codebase already documents and
      guards against elsewhere (`_chainLock`). Fixed with a `SemaphoreSlim` around the
      find-merge-upsert critical section. Also found and fixed, while reviewing this path, a
      second bug that would have silently undermined the fix even without the race:
      `AlertRepository.UpsertAsync`'s `ON CONFLICT` clause omitted
      `evidence_event_ids_json`/`evidence_summary_json`/`estimated_state`, so a coalesced
      alert's merged evidence would never have actually persisted to disk. **Still needs a
      third live retest** to confirm the race fix actually holds under real concurrent load -
      not yet confirmed clean, only confirmed to compile/pass the portable suite.

      This multi-round discovery is exactly the class of bug only real, sustained live traffic
      (not a unit test firing one or two synthetic events) surfaces - worth deliberately
      generating varied real activity (not just one-off single actions) on future validation
      passes to catch anything similar in the remaining rules, and worth specifically retrying
      a burst-style test (many events in a short window) since that's what triggers this class
      of bug specifically.
- [ ] **Security event log collector**: trigger each event ID it claims to understand
      (4624/4625/4648/4672/4697/4698/4702/4720/4732/4735/4964/4663) and confirm a
      `NormalizedEvent` is actually produced with sane field values - the property-index
      mapping (`Prop(N)`) for each event ID was written from documented schemas, never
      confirmed against a live event log's actual property ordering on a real host. Do this
      **first** for 4663 (see decoy section below) since that mapping is newest/least-tested.
- [ ] **PowerShell script-block collector** actually receives Script Block Logging events
      (requires Group Policy / registry to enable that logging first - confirm the collector
      documents this prerequisite correctly).
- [ ] **Registry persistence / service-change / network-connection collectors** each produce
      at least one real event when you deliberately trigger the activity they claim to watch
      (add a Run key, install a service, open an outbound connection).
- [ ] Confirm the sensor doesn't visibly degrade system performance under normal desktop/
      server workload - no informal benchmark exists yet.

## 3. Response actions (Aegis.ResponseActions) - test in an isolated lab only

- [ ] `IsolateEndpointAsync`/`ReleaseIsolationAsync`: confirm the firewall rules created via
      `netsh advfirewall` actually block/restore traffic as intended, and that
      `ReleaseIsolationAsync` removes *only* the rules this executor created (not `name=all`)
      - re-verify this explicitly since it was the site of a dangerous bug caught in v1
      self-review before it ever shipped.
- [ ] `ApplyFirewallRestrictionAsync`/`RemoveFirewallRestrictionAsync`: confirm a rule with a
      real destination IP/port actually applies and is later cleanly removable.
- [ ] **Argument-escaping fix (v2.1)**: confirm a rule name / service name containing a space
      or a double-quote character round-trips correctly through `netsh`/`sc.exe` now (i.e.
      the fix in `ArgumentEscaping.Quote` behaves as intended against the *real* command-line
      parser, not just against the escaping logic in isolation).
- [ ] `TerminateProcessAsync`: confirm the PID-reuse safety check (image path mismatch
      refusal) actually triggers correctly against a real process table.
- [ ] `DisableServiceAsync`: confirm a real service actually stops and its start type
      actually flips to Disabled, and that this is reversible.
- [ ] `RevokeCredentialAsync`/`RestoreCredentialAsync` (`ActiveDirectoryCredentialRevoker`):
      **requires a domain-joined test host with a real AD test account** - confirm disable +
      password-expiry actually happens, `PrincipalServerDownException`/
      `UnauthorizedAccessException` are handled gracefully on a non-domain-joined or
      insufficiently-privileged host, and that re-enabling via `RestoreCredentialAsync`
      actually restores login capability.

## 4. Decoys / deception (v2.1 materialization)

- [ ] Register a `File` decoy via the GUI or IPC and confirm `WindowsDecoyMaterializer`
      actually creates it at the given path with the placeholder content.
- [ ] Register a `Directory` decoy and confirm the same.
- [ ] Register a `Share` decoy and confirm `net share` actually creates a working SMB share
      backed by the temp-rooted folder, and that it's reachable over the network as expected
      (or deliberately not, depending on your firewall posture).
- [ ] Run `auditpol /set /subcategory:"File System" /success:enable /failure:enable` (see
      `docs/OPERATIONS.md`), then touch a materialized File/Directory decoy from a *different*
      process/account and confirm event 4663 actually appears in the Security log with the
      audit rule `WindowsDecoyMaterializer` set - **this is the single least-verified new code
      path in v2.1**, since it depends on SACL semantics, `SeSecurityPrivilege`, and the audit
      policy all being correct together, none of which can be checked outside Windows.
      Confirm the resulting `NormalizedEvent`'s `ObjectId` (from `SecurityEventLogCollector`'s
      4663 property mapping) matches the decoy's registered `Location` closely enough for
      `DeceptionManager.Match` to actually reclassify it as `CanaryAccess`.
- [ ] Confirm `RemoveDecoyAsync` actually deletes the file/directory/share it created.
- [ ] Confirm registering a `ServiceIdentity`/`HoneyCredential`/`Api` decoy correctly reports
      "not auto-materialized" without erroring the registration itself.

## 5. Tamper-evident storage & retention

- [ ] Let the service run and accumulate a few hundred events, then use the GUI's "Verify
      Event Chain" button - confirm it reports Valid.
- [ ] Deliberately corrupt one row's `chain_hash` directly in `aegis.db` (service stopped)
      and confirm verification correctly reports `HashMismatch` at the right sequence.
- [ ] Deliberately delete one row from the middle of the `events` table and confirm
      verification reports `SequenceGap` or `PreviousHashMismatch` (not a false "Valid") -
      this is the specific case the verifier was redesigned to catch.
- [ ] Confirm `EventChainKeyStore`'s DPAPI `LocalMachine`-scoped key survives a service
      restart and (separately) is *not* readable/usable from a different machine's DPAPI
      master key, as intended.
- [ ] Let `RunRetentionAsync` fire (or lower `EventRetentionDays` and wait for the 6-hour
      timer, or trigger it manually for a faster test loop) and confirm only `events` rows
      older than the cutoff are pruned - alerts and the audit log must be untouched.

## 6. RBAC (v2)

- [ ] Create the `AegisDefense Analysts` local group, add a non-administrator test account
      to it, and confirm the GUI run as that account shows "Analyst (read-only)" and that
      every mutating action (policy save, approve/reject, decoy register/remove, patch plan
      actions) is actually refused server-side - not just disabled in the UI (try sending a
      raw IPC request from a script as that account to confirm the server-side check, not
      just the client-side `IsEnabled` binding).
- [x] Confirm an Administrator-group account gets full control as expected. **Verified**
      (after the `TokenImpersonationLevel` fix in §1 above) - top bar shows "Administrator
      (full control)" with no error, Dashboard tiles populate normally.
- [ ] Confirm an account in *neither* group cannot connect at all (the pipe ACL) or, if it
      can connect, is refused every request as `Unknown`.
- [ ] Confirm `WhoAmI`'s `WindowsIdentity` field (v2.1 fix) now actually shows the real
      `DOMAIN\user` string, not a duplicate of the role name.
- [ ] Confirm the group-doesn't-exist soft-fail path: on a host where `AegisDefense
      Analysts` was never provisioned, confirm the service still starts and Administrators
      still work (only Analyst mapping should be affected).

## 7. Signed policy / GUI key management

- [ ] Generate a signing key via the GUI, export the public key, install it on a service
      host, and confirm a signed policy change actually applies.
- [ ] Confirm a policy signed with a *different* key is rejected.
- [ ] **Policy-replay fix (v2.1)**: confirm that resending an old, validly-signed policy
      (lower `Version` than the currently active one) is now rejected with the new
      "not newer than the active version" error, and that this doesn't break normal forward
      progress (each real edit through the GUI increments `Version`, so normal use is
      unaffected).
- [ ] Confirm the DPAPI `CurrentUser`-scoped signing key is unusable from a different Windows
      account, as intended.

## 8. Fleet Hub (v2)

- [ ] Deploy `Aegis.FleetHub` on a real Windows Server (or Linux, it's net8.0/cross-platform)
      behind real TLS (IIS/ARR, nginx, or Caddy terminating HTTPS).
- [ ] Point two or more real `Aegis.Service` hosts at it, confirm heartbeats actually arrive
      and `/healthz` + the fleet status endpoint work as documented.
- [ ] Confirm the empty/missing API key refusal actually stops the Hub from starting in a
      real deployment (not just the in-process integration test).
- [ ] Trigger the same rule ID on two+ hosts in a short window and confirm
      `FeatureSnapshot.CrossHostSimilarHostCount` (and therefore `AutonomyScore`'s
      cross-host-coordination term) actually reflects it.
- [ ] Confirm a host with `FleetSettings.Enabled=true` but an unreachable Hub degrades
      gracefully (local detection/response keeps working, no crash/hang).

## 9. SIEM export

- [ ] Point `SiemForwardingSettings` at a real syslog/SIEM listener (even a simple `nc -ul
      514` for a first pass) and confirm a real alert produces a well-formed CEF line on the
      wire, over both UDP and TCP.
- [ ] Confirm a SIEM outage (listener down) never blocks or delays the local alert/response
      pipeline.

## 10. Patch rollout orchestrator (v2.2 GUI)

- [ ] Create a plan via the GUI's Patching tab, drive it through the full happy path
      (Assessed → MitigationApplied → CanaryTesting → CanaryValidated → RingDeployment →
      Verified → MitigationClosed) and confirm the History panel and `aegis.db` both show
      the complete, correct trail.
- [ ] Force a rollback via an "Unhealthy" health check at both the canary stage and a ring
      stage, confirm the plan lands in `RolledBack` both times.
- [ ] Confirm attempting an action from the wrong stage (e.g. clicking "Begin Ring
      Deployment" before a canary health check) is rejected with a clear error, not a crash
      or a corrupted plan.
- [ ] Restart the service mid-plan and confirm the plan's state survives (it's persisted
      after every transition, but this hasn't been confirmed against a real restart).

## 11. Packaging & CI

- [ ] Run `installer\build-installer.ps1` on a real Windows machine with the WiX Toolset
      installed and confirm it actually produces a working `.msi` - **this has never
      succeeded anywhere but in theory**; the Linux sandbox this was developed in cannot run
      WiX at all (confirmed via real tool errors, not just its own "unsupported" warning).
- [ ] Install via the MSI on a clean VM and confirm the service + console both work, then
      confirm uninstall is clean.
- [ ] Confirm the GitHub Actions `build-and-test-windows` and `build-installer` jobs are
      actually green on `windows-latest` runners (they've been authored to match what was
      manually verified, but the workflow itself has not been observed running).

## 12. Cross-version coverage

The doc's core requirement is spanning old and new Windows plus Windows Server. At minimum,
repeat the "Baseline" and "Telemetry collectors" sections (1-2 above) on:

- [ ] Windows Server 2016 or 2019 (oldest realistic supported server target)
- [ ] Windows Server 2022 or 2025 (newest)
- [ ] Windows 10 (older desktop)
- [ ] Windows 11 (newest desktop)

ETW/WMI availability, Security event log schema quirks, and `netsh`/`sc.exe` behavior have
historically had small but real differences across these - this is exactly the risk
`.NET Framework 4.8` was chosen to minimize at the *language/runtime* level, but it says
nothing about OS API behavior itself.

## 13. Things this checklist deliberately does not cover

Not because they don't matter, but because they need more than "a Windows machine" -
tracked separately:

- A code-signing certificate for the executables/MSI (unsigned binaries that disable
  accounts and isolate hosts will get flagged by AV/SmartScreen, and rightly so).
- A real Active Directory test domain for credential-revocation testing (listed in §3 above,
  but worth calling out again: this is the one item on this list that needs infrastructure
  beyond a single Windows box).
- Load/chaos testing at real fleet scale.
- A third-party security review / penetration test of the deployed system (the in-repo
  `security-review` skill pass covered the source code; it cannot substitute for testing the
  live system).
- Organizational change-management sign-off to actually enable auto-containment in
  production - a code checklist can't grant that authority.
