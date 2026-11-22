# Environment Assumptions: Reference Lab (re-lumma-stealer)

**Status:** Reference assumptions for a documented lab. These are not a description of any real organization.

**Rules**
- Every value below is tagged `[ASSUMED]`. Nothing here is a fact about the author's or any reader's environment.
- Rules, tests, and the playbook depend only on the assumptions listed here. If you change an assumption, update the affected Sigma rule, test fixture, and playbook step in the same commit.
- Readers with a real environment replace each `[ASSUMED]` value with their own answer from `SOC_INTAKE_RULEBOOK.md`, then re-run the tests.
- The local intake answers (`UNKNOWN`) are never filled with values from this file.

---

## 1. Log sources

- `[ASSUMED]` SIEM: generic. Rules are written in Sigma and converted with pySigma. No vendor-specific query language is used.
- `[ASSUMED]` Windows endpoint telemetry collected: Sysmon event IDs 1 (process creation), 3 (network connection), 11 (file create), 13 (registry value set), 22 (DNS query).
- `[ASSUMED]` PowerShell Script Block Logging (4104) is enabled.
- `[ASSUMED]` Security 4663 with a SACL is **not** enabled on browser credential stores. Sysmon 11 records file creation only, so it is not used to detect reads of those files.
- `[ASSUMED]` Proxy or DNS logs include method, URI, and User-Agent where available.
- `[ASSUMED]` Retention: 30 days for endpoint telemetry. Log latency is treated as under 5 minutes.
- `[ASSUMED]` Host mix: Windows 10/11 endpoints only. No macOS or Linux telemetry is assumed for this module.

## 2. Endpoint protection

- `[ASSUMED]` An EDR is present but its telemetry is not assumed to include process memory. Detection logic does not rely on memory artifacts.

## 3. Analysis capacity

- `[ASSUMED]` An isolated analysis VM is available. It has no internet access and no shared folders.
- `[ASSUMED]` No live malware samples are handled in this repository. Analysis uses published reports and synthetic fixtures only.
- `[ASSUMED]` Dynamic analysis is out of scope for this module.

## 4. Response roles (generic, no contacts)

- `[ASSUMED]` Tier 1 analysts triage alerts and can close or escalate using the playbook.
- `[ASSUMED]` Tier 2 approves containment steps.
- `[ASSUMED]` Credential resets and host isolation require Tier 2 approval.
- `[ASSUMED]` Verdicts are fed back through a generic channel named `feedback`. No real channel is referenced.

## 5. Framework and tooling

- `[ASSUMED]` MITRE ATT&CK version: v17, as used in the CISA and FBI advisory AA25-141B.
- `[ASSUMED]` Sigma backend: pySigma. The version is pinned in `requirements.txt` and recorded in the tests.
- `[ASSUMED]` YARA: `yara-python`, tested against synthetic byte strings only.

## 6. Data and compliance

- `[ASSUMED]` All fixtures are synthetic. No real logs, samples, hostnames, IP addresses, or user names appear in the repo.
- `[ASSUMED]` Sample IPs and domains use reserved ranges (RFC 5737 and `.example` names).
- `[ASSUMED]` No monitoring restrictions beyond those in this file apply to the reference lab.

## 7. Acceptance for this reference module

- `[ASSUMED]` CI passes on every module, including the test matrix and the all-tests gate.
- `[ASSUMED]` Each Sigma rule has at least one true-positive and one benign test case.
- `[ASSUMED]` The playbook has been reviewed against the Tier 1 and Tier 2 roles above.

## 8. Explicitly not assumed

- Any real SIEM vendor, EDR vendor, or proxy product.
- Any real contact, team name, or queue.
- Any authority to obtain or handle live malware samples.
- Any telemetry source not listed above.

If a rule, test, or playbook step needs a value that is not listed here, it must stop and ask. It must not infer one.
