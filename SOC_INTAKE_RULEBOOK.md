# SOC Intake Rulebook (repo-safe template)

**Purpose:** Defines what a detection module must know about its target environment before it is built.

**Handling rules**
- This public copy contains placeholders only. Environment details (vendors, hostnames, fleet size, contacts, retention) are kept in a local copy that is never committed.
- Any line that still contains `[ADD:` is treated as `UNKNOWN`. A build must stop at that line and ask for the value. Do not infer, default, or copy an example value.
- Mark each answer `[FROM CHAT]`, `[PROPOSED]`, or `UNKNOWN`.

---

## A. The module

**A1. Module type** → Reverse engineering
**A2. Identifier** → LummaC2 (Lumma Stealer)
**A3. Why this module, now** → `[ADD: your reason]`
**A4. Desired end state** → A Tier 1 analyst can recognise ClickFix-style PowerShell delivery and browser-credential-store access by non-browser processes, then close or escalate using the playbook.
**A5. Out of scope** → Stealer follow-on behaviour beyond a tripwire. No live sample handling in the repo. No offensive capability.

## B. Environment and telemetry

**B1. SIEM** → `[ADD: SIEM product and version]`
**B2. EDR and whether process-creation and memory telemetry are enabled** → `[ADD: EDR product, telemetry enabled]`
**B3. Sysmon deployed?** → `[ADD: yes / no, and version]`
**B4. Sysmon event IDs collected** → `[ADD: event IDs]`
**B5. Security 4663 with SACL on browser or credential paths?** → `[ADD: yes / no, paths covered]`
**B6. PowerShell 4104 script block logging?** → `[ADD: yes / no]`
**B7. Proxy, firewall or DNS logs with method, URI and User-Agent?** → `[ADD: log sources and fields available]`
**B8. Zeek or Suricata sensors?** → `[ADD: yes / no, which]`
**B9. Retention per source (days)** → `[ADD: retention per source]`
**B10. Host mix (Windows, Linux, macOS; server or endpoint)** → `[ADD: host mix]`
**B11. Fleet size** → `[ADD: fleet size range]`
**B12. Log latency** → `[ADD: typical latency]`

## C. Analysis capacity and authority

**C1. Isolated analysis environment available?** → `[ADD: yes / no, description]`
**C2. Who may obtain and handle samples?** → `[ADD: role, not name]`
**C3. Authority covering sample handling** → `[ADD: policy reference]`
**C4. Storage rules for hashes, IOCs and notes** → `[ADD: storage rule]`
**C5. Sandbox or dynamic-analysis tooling** → `[ADD: tooling]`
**C6. Offline unpacking tools** → `[ADD: tooling]`

## D. Thresholds and alert budget

*Intentionally blank.*

## E. Output, repository and CI

**E1. Repository** → ColdCoffeeSec/Defensive-Engineering-Lab
**E2. Folder prefix** → `re-`
**E3. May the CI discovery pattern be changed?** → Yes `[PROPOSED]`. Confirm.
**E4. ATT&CK version to pin** → v17 `[PROPOSED]`
**E5. Sigma backend for conversion** → `[ADD: backend and version]`
**E6. Language and tooling versions** → `[ADD: output of pip show pysigma yara-python pytest]`

## F. Response and ownership

**F1. Tier 1 queue and hours** → `[ADD: queue name, hours]`
**F2. Escalation roles for Tier 2 and Tier 3** → `[ADD: role names only, no personal contacts]`
**F3. Credential reset authority** → `[ADD: role]`
**F4. Containment authority** → `[ADD: role]`
**F5. Feedback channel for analyst verdicts** → `[ADD: channel]`
**F6. Existing playbooks to align with** → `[ADD: playbook references]`

## G. Data and compliance

**G1. Data classes in fixtures** → Synthetic only `[PROPOSED]`
**G2. Redaction rules for any real log used** → `[ADD: redaction rule]`
**G3. Legal or contractual limits on monitoring** → `[ADD: policy reference]`
**G4. Sign-off before a rule goes to production** → `[ADD: approving role]`

## H. Acceptance

**H1. What "done" means** → CI green on the module, baseline recorded, playbook reviewed by Tier 2 `[PROPOSED]`
**H2. What must be true before production** → Baseline and real-data measurement complete locally, and sign-off under G4 `[PROPOSED]`
**H3. Not accepted as evidence** → Synthetic fixture scores alone `[PROPOSED]`

---

## Submission checklist

- [ ] A3 answered
- [ ] B1 to B12 answered
- [ ] C1 to C6 answered
- [ ] E5 and E6 answered
- [ ] F1 to F6 answered
- [ ] G2 to G4 answered
- [ ] Every `[PROPOSED]` item confirmed or corrected
- [ ] No `[ADD:` placeholders remain in the local copy
