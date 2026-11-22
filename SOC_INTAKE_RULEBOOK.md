# SOC Intake Rulebook

> **TEMPLATE. Do not fill this file in inside the repository.** Copy it to a private location outside the repository, answer the questions there, and never commit the filled copy. Every field below must keep its `[ADD: ...]` placeholder in the repository. The `docs-checks` suite fails if any field holds a value.

**Purpose:** Fill this in before starting any new Detection-as-Code module. The blueprint skill uses your answers to set thresholds, pick log sources, and decide what it can and cannot claim. If a section is blank, the blueprint will mark it as unverified and will not guess.

**How to answer:** Write the answer after each `→`. Write `unknown` if you don't know. Do not guess. Leave a blank line for each question you skip.

---

## A. The module

**A1. Module type** → [ADD: weakness CWE / technique ATT&CK / reverse engineering / cloud / network / other]
**A2. Identifier** → [ADD: CWE number, ATT&CK ID, malware family name, or service name]
**A3. Why this module, now** → [ADD: threat, incident, audit finding, or training goal, in one or two sentences]
**A4. Desired end state** → [ADD: what a Tier 1 analyst should be able to do after this module ships]
**A5. Explicitly out of scope** → [ADD: for example, "no stealer follow-on behaviour beyond a tripwire"]

## B. Environment and telemetry

**B1. SIEM** → [ADD: Splunk, Sentinel, Elastic, other, and version]
**B2. EDR** → [ADD: product, and whether process creation and memory telemetry are enabled]
**B3. Sysmon deployed?** → [ADD: yes/no; version; config source]
**B4. Sysmon event IDs collected** → [ADD: tick and list the IDs: 1, 3, 4, 7, 8, 10, 11, 13, 22, other]
**B5. Windows Security 4663 with SACL on browser or credential paths?** → [ADD: yes/no; which paths]
**B6. PowerShell 4104 script block logging?** → [ADD: yes/no]
**B7. Proxy, firewall or DNS logs with HTTP method, URI and User-Agent?** → [ADD: product; fields available]
**B8. Zeek or Suricata sensors?** → [ADD: yes/no; which]
**B9. Retention for each source** → [ADD: days]
**B10. Host mix** → [ADD: percentage Windows, Linux, macOS; server or endpoint]
**B11. Fleet size** → [ADD: endpoints; active users]
**B12. Log latency** → [ADD: typical delay from event to searchable]

## C. Analysis capacity and authority

**C1. Isolated analysis environment available?** → [ADD: yes/no; describe, without network details]
**C2. Who may obtain and handle samples?** → [ADD: roles; names are optional]
**C3. Authority for sample handling** → [ADD: the policy or agreement that covers this work]
**C4. Storage rules for hashes, IOCs and analysis notes** → [ADD: where they live; retention]
**C5. Sandbox or dynamic-analysis tooling** → [ADD: product; output types you can export]
**C6. Offline unpacking tools** → [ADD: list]

## D. Thresholds and alert budget

**D1. Acceptable false positives per day, by severity** → [ADD: for example, "high: 1 per 10,000 endpoint-days"]
**D2. Minimum detection rate you'd accept, and why** → [ADD: number and reason]
**D3. Maximum alert volume for a new rule before tuning** → [ADD: alerts per day]
**D4. How long a rule may stay at test status** → [ADD: days]
**D5. Review cadence for revalidation** → [ADD: monthly, quarterly, after each new build]

## E. Output, repository and CI

**E1. Repository** → [ADD: owner/name]
**E2. Folder prefix** → [ADD: cwe-, ttp-, re-, cloud-, net-, other]
**E3. May the CI discovery pattern be changed?** → [ADD: yes/no; who approves]
**E4. ATT&CK version to pin** → [ADD: for example, v17]
**E5. Sigma backend for conversion** → [ADD: pySigma backend name, or sigma-cli target]
**E6. Language and tooling versions** → [ADD: Python, pytest, yara-python, pySigma]

## F. Response and ownership

**F1. Tier 1 queue and hours** → [ADD: team; coverage hours]
**F2. Escalation contacts for Tier 2 and Tier 3** → [ADD: roles]
**F3. Credential reset authority** → [ADD: who can reset; approval needed?]
**F4. Containment authority** → [ADD: who can isolate hosts]
**F5. Feedback channel for analyst verdicts** → [ADD: ticket system; field names if fixed]
**F6. Existing playbooks to align with** → [ADD: names or paths]

## G. Data and compliance

**G1. Data classes that may appear in fixtures** → [ADD: usually "none real; synthetic only"]
**G2. Redaction rules for any real log that is used** → [ADD: describe]
**G3. Legal or contractual limits on monitoring** → [ADD: for example, employee monitoring rules, privacy review]
**G4. Who signs off before a rule goes into production** → [ADD: role]

## H. Acceptance

**H1. What "done" means for this module** → [ADD: CI green, baseline recorded, playbook approved, rule in production, other]
**H2. What must be true before production** → [ADD: list]
**H3. What you will not accept as evidence** → [ADD: for example, synthetic fixture scores alone]

---

## Submission checklist

- [ ] Sections A, B and E are complete. The blueprint will not start without them.
- [ ] C is complete if the module involves any sample handling.
- [ ] D thresholds are numbers, not adjectives.
- [ ] Every "unknown" is listed in a note at the end, so the blueprint can mark it.
- [ ] No real secrets, hostnames, customer data or real IOCs are included in these answers.

**Notes (unknowns and open questions):**
