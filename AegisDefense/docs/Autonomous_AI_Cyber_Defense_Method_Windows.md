# Autonomous AI Cyber Defense

*A Research and Engineering Method for Windows Endpoints and Windows Server*

Behavioral detection • attack-state reasoning • prediction • deception • containment • virtual mitigation
Working architecture / research roadmap — Version 0.1, August 2026

> This is the source research document `Aegis Autonomous Defense` (see `../README.md`) implements. Reproduced here as the canonical reference the code's comments cite by section number (e.g. "doc §14").

## 1. Executive Summary

This document defines a defensive research method for detecting and containing fast,
adaptive, potentially autonomous cyber attacks against Windows PCs and Windows Server
environments. The central premise is that attribution to a particular AI model is neither
necessary nor reliably possible. The defender should instead identify machine-speed
adaptation, correlate actions into an evolving attack state, predict likely next
objectives, and apply bounded defensive responses before the attack chain completes.

The proposed system is not an LLM-based antivirus. It is a layered endpoint and server
defense architecture combining deterministic telemetry, behavioral rules,
statistical/ML models, graph correlation, attack-state estimation, deception, and a
constrained AI reasoning layer. High-impact remediation remains policy controlled and
auditable.

## 2. Research Objective

Primary research question: **Can a defensive system recognize and interrupt an adaptive
autonomous adversary's objective before the adversary discovers a successful path through
the infrastructure?**

Secondary objectives:

- Distinguish ordinary administration, conventional malware, scripted automation, and
  highly adaptive attack behavior using observable telemetry.
- Represent many low-level events as one evolving attack campaign rather than isolated
  alerts.
- Estimate the attacker's current objective and likely next objective.
- Contain high-confidence attacks automatically while minimizing false-positive business
  disruption.
- Use deception to create high-confidence tripwires and waste adversarial exploration
  effort.
- Generate safe temporary mitigations ("virtual patches") while authoritative vendor
  remediation is prepared and deployed.
- Measure whether the approach improves mean time to detect, contain, and remediate
  compared with conventional alert-centric defenses.

## 3. Threat Model

The system assumes an attacker may use autonomous or semi-autonomous agents for
reconnaissance, vulnerability discovery, exploitation attempts, privilege escalation,
credential access, persistence, lateral movement, and adaptation after failures. The
defensive design does not depend on proving that an AI generated a command or payload.

### 3.1 Observable characteristics

- High action frequency and unusually short time between observation and the next
  technique.
- Rapid switching of techniques after a failure.
- Systematic enumeration across identities, services, shares, endpoints, and
  infrastructure.
- Repeated hypothesis-test-adapt cycles.
- Cross-host or cross-service coordination.
- Novel payloads with familiar behavioral consequences.
- Progression through recognizable ATT&CK-like objectives even when individual tools or
  binaries are previously unseen.

## 4. Core Defensive Principle: Detect Effects, Not the AI Brand

An autonomous attacker still has to cause observable effects in the target environment. It
must authenticate, execute, enumerate, create network connections, manipulate files or
registry state, request privileges, access credentials, establish persistence, or move
between systems. These effects provide stable defensive features even when code, prompts,
tooling, and exploit selection change.

## 5. Windows Telemetry Plane

| Telemetry domain | Examples | Research value |
|---|---|---|
| Process | Process creation, parent/child chain, command line, signer, image hash | Execution lineage and technique transitions |
| ETW / kernel | Process, file, image load, network and selected kernel providers | High-rate local behavioral stream |
| PowerShell / AMSI | Script-block and content inspection signals | Script execution and obfuscation indicators |
| Identity | 4624, 4625, 4648, 4672 and related audit events | Account abuse and privilege context |
| Services / tasks | Service creation/change; scheduled task creation/change | Persistence and privileged execution |
| Registry | Run keys, services, security-sensitive configuration | Persistence/configuration tampering |
| Files | Executable creation, mass changes, entropy and protected-path writes | Payload and destructive behavior |
| Network | DNS, connections, ports, byte counts, destinations | C2, scanning, staging and lateral movement |
| SMB/RDP/WinRM/WMI | Remote management and administrative activity | Lateral movement |
| Drivers | Load events, signature status, known vulnerable driver metadata | Kernel-level risk |
| Defender/security | Detection events and security-control configuration changes | Defense evasion |
| Active Directory | Account/group/GPO/Kerberos-sensitive changes | Identity and domain attack state |

*Implemented by: `Aegis.Sensor` (`SecurityEventLogCollector`, `ProcessTraceCollector`,
`ServiceChangeCollector`, `RegistryPersistenceCollector`, `PowerShellScriptBlockCollector`,
`NetworkConnectionCollector`).*

## 6. Normalized Event Model

All telemetry should be normalized into a common event schema so correlation does not
depend on a particular Windows provider.

```
Event {
  timestamp
  host_id
  user_id
  process_id
  parent_process_id
  process_hash
  signer
  action_type
  object_type
  object_id
  source_ip
  destination_ip
  destination_port
  privilege_context
  result
  confidence
  raw_event_reference
}
```

*Implemented by: `Aegis.Core.Events.NormalizedEvent`.*

## 7. Feature Engineering

Features should exist at several time scales: per event, per process tree, per identity,
per host, and across the enterprise.

- Process rarity and parent→child rarity.
- Command/script complexity, obfuscation indicators, and execution context.
- Authentication failure/success transitions and unusual logon types.
- Rate of remote-host contacts and newly contacted systems.
- Privilege changes and security-control modifications.
- Persistence creation shortly after suspicious execution.
- Credential-sensitive access followed by remote authentication.
- Technique-switching frequency after failed actions.
- Time between reconnaissance result and subsequent action.
- Similarity of behavior occurring simultaneously across several hosts.

*Implemented by: `Aegis.Core.Features.HostBehaviorProfile`, `IProcessBaseline`,
`CommandComplexityHeuristic`.*

## 8. Multi-Engine Detection

No single detector should decide the full incident. The proposed design uses independent
engines whose outputs are fused.

| Engine | Role | Strength |
|---|---|---|
| Rule engine | Known dangerous combinations and policy violations | Deterministic, explainable |
| Statistical/ML engine | Host/user/process anomaly detection | Finds previously unseen deviations |
| Graph engine | Relationships among processes, users, hosts, services and destinations | Reconstructs attack chains |
| Sequence model | Temporal progression and technique transitions | Recognizes evolving campaigns |
| Threat-intelligence engine | Known hashes, infrastructure, vulnerabilities and TTP context | External context |
| AI reasoning layer | Summarizes evidence, maintains hypotheses and recommends bounded actions | Contextual reasoning |

*Implemented by: `Aegis.Core.Rules.RuleEngine` + `BuiltInRules` (deterministic engine; the
MVP's 16 rules). The statistical/graph/sequence/threat-intel/AI-reasoning engines are
represented as pluggable score inputs (`mlAnomalyScore`, `vulnerabilityExposureScore`,
`attackSequenceScore` parameters on `HostRiskCalculator.Compute`) — see
`ARCHITECTURE.md#extensibility-seams` for where to plug a real model in.*

## 9. Attack-State Graph

The central data structure is a continuously updated graph. Nodes represent hosts,
identities, processes, files, services, credentials/tokens, destinations and security
events. Edges represent actions or relationships. This allows the system to answer not
only "what happened?" but "what campaign is forming?"

```
Identity ──logs_on_to──> Host
Host ──spawns──> Process
Process ──writes──> File
Process ──connects_to──> Destination
Process ──creates──> Service
Identity ──accesses──> RemoteHost

Event stream → graph update → attack-state inference → response policy
```

*Implemented by: `Aegis.Core.Graph.AttackStateGraph`.*

## 10. Attack-State Estimation

Instead of assigning only a malware probability, maintain hypotheses about the actor's
current objective. Example states include Initial Access, Execution, Persistence,
Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement,
Collection, Command-and-Control, and Exfiltration.

```
Observed:
  unusual logon
  → enumeration
  → suspicious script execution
  → failed technique
  → immediate alternate remote-management technique
  → privilege change
  → contacts to many internal hosts

Inferred state:
  Current objective: Discovery / Lateral Movement
  Confidence: high
  Predicted next objectives:
    Credential Access
    Persistence
    Additional Lateral Movement
```

*Implemented by: `Aegis.Core.Estimation.AttackStateEstimator` + `NextObjectivePredictor`.*

## 11. Autonomy / Adaptation Scoring

An AutonomyScore should be treated as a behavioral risk feature, not proof that an AI is
responsible. Its purpose is to identify attack behavior that is adapting quickly enough to
require machine-speed defense.

```
AutonomyScore = weighted(
    action_frequency,
    technique_switching_rate,
    failure_adaptation_rate,
    reconnaissance_depth,
    target_selection_change_rate,
    cross_host_coordination,
    result_to_next_action_latency
)
```

The weights and thresholds should be learned and calibrated from controlled experiments.
**The score should never be the sole reason for destructive remediation.**

*Implemented by: `Aegis.Core.Scoring.AutonomyScoreCalculator`. The "never sole reason"
constraint is enforced in `ResponsePolicyEngine.IsAutonomyDominated` — a high-impact
response is capped at Restrict when AutonomyScore is the only elevated component.*

## 12. Composite Risk Engine

Production implementation should normalize component scores, calibrate them against
false-positive cost, and include confidence and evidence quality. A transparent evidence
trail must accompany every high-impact decision.

```
HostRisk =
    ProcessBehavior
  + IdentityRisk
  + NetworkRisk
  + PersistenceRisk
  + CredentialRisk
  + LateralMovementRisk
  + FileBehavior
  + VulnerabilityContext
  + MLAnomalyScore
  + AttackSequenceScore
  + AutonomyScore
```

*Implemented by: `Aegis.Core.Scoring.HostRiskCalculator`. `HostRiskBreakdown` carries every
named component plus `Confidence` and `ContributingFindings` — the evidence trail shown in
the GUI's Alerts tab.*

## 13. Predictive Defense

Once the attack state is known, the defender can estimate likely next states and increase
telemetry or temporarily restrict only the pathways relevant to those states. This is
preferable to waiting for a complete compromise.

- If lateral movement probability rises: increase SMB/WinRM/RDP telemetry and enforce
  narrower access for the suspect host.
- If credential access probability rises: increase monitoring around credential-bearing
  processes and privileged authentication.
- If persistence probability rises: watch service/task/autorun changes with stricter
  policy.
- If exfiltration probability rises: increase egress inspection and apply approved
  data-loss controls.

*Implemented by: `NextObjectivePredictor.RecommendedPreemptiveAction` and
`DefenseEngine.ActOnPrediction` — a high-confidence predicted next objective triggers a
proactive, always-safe telemetry increase even before risk crosses an alert threshold.*

## 14. Response Policy and Safety Boundaries

Automated response must be graduated:

| Risk | Mode | Examples |
|---|---|---|
| Low | Observe | Record and correlate |
| Moderate | Enrich | Increase telemetry; collect process tree and network context |
| Elevated | Restrict | Limit suspicious process/network capabilities under policy |
| High | Contain | Terminate/quarantine confirmed malicious process; isolate endpoint |
| Critical | Enterprise response | Contain host, protect identities, hunt related evidence across estate |

High-impact actions such as disabling privileged identities, broad firewall changes,
service shutdown, or production-server isolation should require explicit policy approval
or human authorization unless the organization has pre-authorized a narrowly defined
emergency playbook.

*Implemented by: `Aegis.Core.Policy.ResponsePolicyEngine` + `DefensePolicy` (signed,
GUI-editable). The GUI's Approvals tab is the human-authorization path; the signed policy's
`EmergencyPlaybook` is the pre-authorized path.*

## 15. Deception Layer

Deception provides unusually strong evidence because legitimate users and software should
have no reason to interact with carefully designed decoys. The objective is not merely to
detect malware but to expose reconnaissance and decision-making.

- Decoy files/directories with instrumented access.
- Decoy service identities with no legitimate authentication path.
- Honey credentials/tokens that cannot grant real privilege.
- Decoy shares, APIs or services inside an isolated honeynet.
- Canary resources whose access immediately raises incident confidence.

Decoys must never contain real secrets and should be architected so compromise of the
deception environment cannot create a path into production.

*Implemented by: `Aegis.Core.Deception.DeceptionManager` / `DecoyResourceDefinition` (whose
`GrantsRealPrivilege` is hard-coded `false`, not just documented) and the `AEG-014`
canary-access rule (0.97 confidence, Critical severity).*

## 16. Vulnerability and Patch Intelligence

Maintain an asset/vulnerability graph for every managed endpoint/server:

```
Host
 ├─ Windows build / edition
 ├─ installed KBs
 ├─ applications + versions
 ├─ drivers
 ├─ listening services
 ├─ exposed interfaces
 ├─ configuration
 ├─ business criticality
 └─ known vulnerability exposure
```

Prioritization should combine vulnerability severity with actual exposure, reachability,
observed exploitation, privilege level and business criticality. A vulnerable component
that is installed but unreachable should not receive the same operational priority as an
actively exploited internet-facing service.

*Implemented by: `Aegis.Core.Vulnerability.VulnerabilityPrioritizer`.*

## 17. Virtual Mitigation Instead of AI-Written OS Patches

Generating arbitrary binary patches for Windows components is unsafe. The more practical
autonomous-defense target is temporary mitigation: reduce or remove exploit preconditions
until an authoritative vendor fix is tested and deployed.

- Restrict an affected protocol or interface.
- Apply a narrowly scoped Windows Firewall rule.
- Disable or constrain a vulnerable optional feature where operationally acceptable.
- Tighten service ACLs or network reachability.
- Block a confirmed malicious process lineage or artifact through approved endpoint
  controls.
- Revoke/rotate exposed credentials or tokens through an authorized identity workflow.
- Increase telemetry around the vulnerable component.

*Implemented by: `Aegis.Core.Response.IResponseExecutor` /
`Aegis.ResponseActions.WindowsResponseExecutor` (firewall rules via `netsh`, service
disable via `sc.exe`, process termination with an image-path safety check). Credential
revocation is intentionally left as an unimplemented extension point pending an
organization-specific identity-workflow integration.*

## 18. Safe Patch-Orchestration Workflow

1. Inventory and identify the exact affected component/version.
2. Map authoritative vendor advisories and applicable updates.
3. Determine exploitability in the organization's configuration.
4. Apply temporary mitigation if exploitation risk is immediate.
5. Test the vendor update against a representative VM/canary system.
6. Validate application, service, boot, authentication and network health.
7. Deploy to a small canary group.
8. Observe telemetry and rollback criteria.
9. Progressively deploy to larger rings.
10. Verify update state and close the temporary mitigation only after validation.

*Not automated by the MVP — `VulnerabilityPrioritizer.RecommendMitigations` produces the
step-9/10 tracking note as a reminder; the ringed-rollout orchestration itself is future
work (see `ARCHITECTURE.md#not-yet-implemented`).*

## 19. Proposed Windows Agent Architecture

```
Windows Endpoint / Server
        │
        ├─ C++ low-level sensor
        │    ETW / process / image / selected network telemetry
        │
        ├─ C# service
        │    normalization / local cache / policy / secure transport
        │
        └─ local response module
             bounded containment actions
                    │
                    ▼
             Secure Event Bus
                    │
       ┌────────────┼─────────────┐
       ▼            ▼             ▼
   Rule Engine   ML Service   Graph/Sequence Engine
       └────────────┼─────────────┘
                    ▼
              Attack State
                    ▼
             Defender Reasoner
                    ▼
              Policy Engine
                    ▼
        Response / SOC / Evidence
```

*Implemented as (see `ARCHITECTURE.md` for the full mapping and why the "C++ sensor" became
a C#/WMI+EventLog sensor for the MVP): `Aegis.Sensor` (collectors) → `Aegis.Service`
(`DefenseEngine`, in-process — the "Secure Event Bus" is an in-process callback pipeline for
the MVP, not a separate network hop) → `Aegis.Core` engines → `Aegis.ResponseActions` →
`Aegis.Data` (evidence) / `Aegis.Ipc` (GUI/SOC).*

## 20. Recommended Technology Split

| Component | Candidate technology | Reason |
|---|---|---|
| Endpoint sensor | C++ | Low overhead and direct Windows telemetry integration |
| Endpoint service/UI | C#/.NET | Fast Windows engineering and service integration |
| Event transport | gRPC / message bus | Structured streaming and backpressure |
| Feature/ML services | Python initially; optimized runtime later | Rapid experimentation |
| Graph correlation | Graph-capable store or optimized custom graph layer | Campaign relationships |
| Time-series/event store | Columnar/event-oriented storage | High-volume telemetry |
| Reasoning service | Constrained AI/LLM + deterministic tools | Context and explanation, not raw authority |
| Policy engine | Deterministic signed policies | Safety and auditability |

*Actual MVP choices and rationale — see `ARCHITECTURE.md#technology-choices`.*

## 21. Data and Model Development

A useful dataset should contain complete sequences, not only isolated malicious files:
normal administration traces, software installation/IT-management activity, benign
automation, conventional malware in isolated labs, scripted red-team/emulation traces in
owned test environments, adaptive agent simulations in isolated authorized ranges, and
failure-and-retry sequences. Labels should include event-level labels, technique/objective
labels, campaign/session identifiers, timestamps, host/identity relationships, and
success/failure.

*Not implemented — this is a data-collection program, not a code component. `NormalizedEvent`
and `Alert`/`RuleFinding` carry every field this section requires for labeling.*

## 22. Experimental Metrics

- Detection recall and precision at event, host and incident level.
- False positives per endpoint/day and per server/day.
- Time from initial malicious behavior to attack-state recognition.
- Time from recognition to containment.
- Percentage of attack chains interrupted before lateral movement or privilege escalation.
- Next-objective prediction top-1/top-k accuracy.
- AutonomyScore separation between human administration, scripted automation and adaptive
  attack simulations.
- CPU, RAM, disk and network overhead of endpoint telemetry.
- Business disruption caused by automated response.
- Rollback rate and patch/mitigation success rate.

*Not automated — requires the isolated-range evaluation harness from WP10.*

## 23. Research Work Packages

WP1 Telemetry Sensor · WP2 Baseline Behavior · WP3 Attack Graph · WP4 Sequence Detection ·
WP5 Adaptation Detection · WP6 Predictive Defense · WP7 Deception · WP8 Response Engine ·
WP9 Vulnerability/Mitigation · WP10 Evaluation.

*Status: WP1/WP3/WP5(partial)/WP7/WP8/WP9 have MVP implementations in this repo. WP2 has a
seam (`IProcessBaseline`) but only a simple in-memory frequency baseline, not a trained
model. WP4 (learned sequence model) and WP10 (isolated-range evaluation) are not
implemented — see `ARCHITECTURE.md#not-yet-implemented`.*

## 24. Minimum Viable Prototype (MVP)

- Windows 11 + Windows Server 2022/2025 lab.
- C# Windows service collecting process, authentication, service/task and selected network
  events.
- ETW-based process/image/file telemetry where useful.
- Central event receiver and normalized event database.
- Process/identity/host graph.
- Ten to twenty high-confidence behavioral correlation rules.
- Simple anomaly model for per-host behavior.
- Attack-state classifier for Discovery, Credential Access, Persistence and Lateral
  Movement.
- One reversible containment action: isolate a test endpoint while preserving management
  connectivity.
- A small deception package with canary files and decoy identities.
- Evaluation dashboard showing evidence, risk score, state transitions and containment
  time.

*This repository implements this section directly — see `README.md`'s component table.*

## 25. Suggested Development Sequence

Sensor reliability → deterministic correlation/evidence graph → attack-state
representation → dataset collection → sequence/anomaly models → adaptation/AutonomyScore
experiments → next-objective prediction → deception integration → bounded automated
containment → vulnerability prioritization/virtual mitigation → AI reasoning/explanation
layer last.

## 26. Key Research Risks

| Risk | Control |
|---|---|
| False positives isolate critical servers | Role-aware thresholds, canaries, approval policies, reversible actions |
| Attacker poisons telemetry or AI context | Trust boundaries, signed telemetry, deterministic evidence validation |
| LLM hallucination causes remediation error | LLM cannot directly execute unrestricted actions; policy engine gates all actions |
| Telemetry volume becomes excessive | Local aggregation, sampling where safe, role-specific providers |
| Model overfits lab attacks | Diverse benign workloads, unseen scenarios, temporal holdouts |
| Deception creates operational risk | Strict isolation and zero real credentials |
| Automatic mitigation breaks applications | Canary deployment, health checks, rollback and human approval for broad changes |

## 27. Where the Novel Work Is

The most promising research contribution is not another malware classifier. It is the
combination of temporal attack-state reconstruction, adaptation-rate measurement,
next-objective prediction, and policy-bounded autonomous containment:

- Formal definition and validation of machine-speed adaptation features.
- Graph + sequence fusion for cross-host attack-state estimation.
- Prediction of the next adversarial objective with uncertainty.
- Dynamic escalation of telemetry based on predicted attack state.
- Deception feedback incorporated into the attack graph.
- Measurable decision rules for when autonomous containment is safer than waiting for a
  human.
- Virtual mitigation generation constrained to reversible, vendor-supported or
  administrator-approved controls.

## 28. Reference Incident Context

This research direction was motivated in part by August 2026 public reporting around Black
Hat demonstrations and security research describing autonomous agents that could discover
vulnerabilities, adapt after failures, coordinate information, and progress through
infrastructure. These reports should be treated as motivating case studies; the
architecture in this document is designed to remain valid regardless of the specific AI
model or incident.

Public articles supplied for context:
- CNBC, 8 Aug 2026 — Hugging Face / AI hacking and Black Hat coverage.
- Forbes, 7 Aug 2026 — reporting on an OpenAI security research incident and
  autonomous-agent behavior.

## 29. Defensive Scope and Governance

All testing should occur on systems owned by or explicitly authorized for the research.
The platform should preserve forensic evidence, log every automated decision, support
rollback, and enforce least privilege. Autonomous reasoning must not receive unrestricted
administrative capability; execution should occur only through a narrow, deterministic
response API with signed policies and auditable authorization.

*Implemented by: `PolicySignature` (RSA-SHA256 signed policies), `IAegisLogger.LogAudit`
(every automated/approved decision), `IResponseExecutor`'s closed, enumerated action set
(no "run arbitrary command" method exists anywhere in the codebase).*

## 30. Immediate Next Step

Start with WP1–WP3: build the Windows telemetry sensor, normalized event pipeline, and
attack graph. These components produce the dataset needed for every later ML and autonomy
experiment. Only after the graph reliably reconstructs known test scenarios should work
begin on AutonomyScore and next-objective prediction.
