# Testing: re-lumma-stealer

**Last updated:** 2026-11-22. **Status:** the three Sigma rules, two YARA rules, config extractor and mutation tests (M1 to M7) were all run in the official `python:3.12` container on Python 3.12, the version CI uses. Result: 175 passed in 1.36s. The cwe-078 module suite and the documentation checks were run in the same container (section 9). **The baseline and real-data measurements have not been run (section 6) and no metric targets are set. The CI discovery pattern was extended on this branch to include `re-*` and `docs-*`, but the workflow has not been run on GitHub, so the CI result is unverified.**

Tags follow `CTI_CONTEXT.md`: **[V]** verified by a run shown below, **[A]** analyst-derived, **[U]** unverified, **[ASSUMED]** from `ENVIRONMENT_ASSUMPTIONS.md`.

## 0. Roadmap status

| Step | Pass condition | Status |
|---|---|---|
| 2. CTI_CONTEXT.md, ANALYSIS.md | Every claim tagged V or U. Hash only for samples. | Written. Claims re-checked on 2026-11-22 against raw downloaded pages. ATT&CK IDs and names also checked against the versioned v17 pages on 2026-11-22 (section 8.1). No pytest applies. |
| 3. Sigma rules | Each rule has `falsepositives` and a source-limits note. | Done. Rules 001, 002 and 003 pass their cases (section 9). **Rule 003 is written, low confidence.** It replaces the earlier "not written" decision. Decision made 2026-11-22 by the repo owner (section 4.2). |
| 4. YARA rules | Rules compile and match their fixtures. | Done for what was claimed: both rules compile with **no warnings** under `error_on_warning=True` and match their synthetic fixtures. The patterns are published strings, low confidence **[A]**, never run on a real sample. |
| 5. IR_PLAYBOOK.md, iocs.csv | All indicators defanged. | Done. Playbook is **unreviewed**. 9 hashes matched exactly against the CISA page. |
| 6. Fixtures and pytest suite | Suite runs, ChaCha20 round trip passes. | Done. Full suite passes in the container (section 9). |
| 7. Mutation run | Every break turns its named cases red. | Done. M1 to M7 each turn exactly the expected cases red (section 5). |
| 8. TESTING.md with baseline | Baseline recorded. | This file. **Baseline not run** (section 6). |
| 9. CI change | Discovery pattern includes this module. Do not claim CI passed until it is green. | The `find` in the workflow now matches `./re-*/tests` and `./docs-*/tests`. The new discovery command was run locally and lists three folders. **The workflow itself has not run on GitHub; CI status is unverified.** |
| Docs | Documentation checks run in the same matrix. | Done: the `docs-checks` suite passes in the container (section 9.4) and every check has a mutation proof. See [docs-checks](../docs-checks/README.md). |

## 1. Environment of the runs below

| Item | Value |
|---|---|
| Image tag | `python:3.12` |
| Image digest | `python@sha256:5411fa1b302c43f510324381162b5f5d0d93b9ee2af538f09d944f0d290ee3cb` |
| Image created | 2026-11-05T09:40:41.434673518Z |
| Python in image | 3.12.16 (see output in section 9) |
| Container runtime | Docker Desktop, client 29.9.3, server 29.9.3, Linux engine, `linux/amd64` |
| Repo mount | the whole repository mounted **read-only** at `/repo`, tests run from there as CI runs them; `PYTHONDONTWRITEBYTECODE=1`, so the run cannot change the repo |
| Dependencies | installed in the container with `pip install -r tests/requirements.txt`; versions are printed in section 9 and match the pins |
| Network | the container had network access for `pip install` only; tests make no network calls |

An earlier run on Windows with Python 3.14 covered only the Sigma, extractor and M1 to M4 tests, because `yara-python` has no wheel for 3.14. It is superseded by the container run and its output is not reproduced here. Python 3.14 is not a supported target for the YARA tests.

## 2. What the tests do and do not show

- Sigma rules are evaluated by `tests/sigma_eval.py`, a small Sigma subset that raises on any syntax it does not know. Each rule is also parsed by pySigma. **No pySigma backend conversion was tested**, because no SIEM or backend is assumed (`ENVIRONMENT_ASSUMPTIONS.md` section 1).
- Cases are synthetic Windows event XML in the shape Windows writes for Sysmon 1 and Security 4663. YARA fixtures are synthetic filler bytes with the rules' own strings dropped in. No real log or sample is used.
- A pass shows the rule logic matches the labelled cases. **It is not a detection rate or a false-positive rate.**
- The documentation is tested too: the `docs-checks` suite at the repository root checks links, quoted counts, tagged commands, the module table, rule-file fields, the safety rules and the intake template, and each check has a mutation test ([docs-checks](../docs-checks/README.md)). Its output is in section 9.4. It does not judge whether a claim is true.
- Rule 003 is a low-confidence rule on two User-Agent strings. Its fixtures prove the logic only. See section 4.2 for what they cannot show.
- Rule 002 needs a 4663 SACL that the reference environment does not enable. Its cases prove logic only. **In the reference environment the rule cannot fire.**
- The YARA rules were written from published strings, not from sample analysis. They are low confidence. They may miss the family they name and will match benign software. A fixture pass says nothing about either.
- The config extractor parses **our own** blob schema (`ANALYSIS.md` section 3.3). The round trip shows the parser matches that schema. It says nothing about real Lumma configs.
- The ChaCha20 call is checked against a zero-key, zero-nonce keystream vector (`test_cipher_known_answer_zero_key`). That test passed **[V]**. The vector's attribution to a published test-vector set is not verified from a fetched source **[U]**; the test only shows the cryptography library produces that value.

## 3. Coverage matrix: rule 001 (ClickFix PowerShell / mshta)

Case counts by category: benign-near-miss: 10, clickfix-cradle: 2, clickfix-encoded: 6, clickfix-mshta: 2, documented-gap: 5. Total 25.

| ID | Category | Technique | Expected | Description |
|---|---|---|---|---|
| R1-P01 | clickfix-encoded | T1204 / T1059.001 | alert | Run dialog paste, -enc with hidden window |
| R1-P02 | clickfix-encoded | T1204 / T1059.001 | alert | Abbreviation -e |
| R1-P03 | clickfix-encoded | T1204 / T1059.001 | alert | Full -EncodedCommand |
| R1-P04 | clickfix-encoded | T1204 / T1059.001 | alert | pwsh with -ec |
| R1-P05 | clickfix-encoded | T1204 / T1059.001 | alert | Abbreviation -enco |
| R1-P06 | clickfix-encoded | T1204 / T1059.001 | alert | Upper-case paths and flags (case-insensitive match) |
| R1-P07 | clickfix-cradle | T1204 / T1059.001 | alert | iex with irm against a URL |
| R1-P08 | clickfix-cradle | T1204 / T1059.001 | alert | WebClient DownloadString piped to iex |
| R1-P09 | clickfix-mshta | T1204 / T1218.005 | alert | mshta against an https URL |
| R1-P10 | clickfix-mshta | T1204 / T1218.005 | alert | mshta against an http URL on a reserved address |
| R1-N01 | benign-near-miss | T1204 / T1059.001 | no alert | Scheduled task host runs an approved encoded script (same command as P01) |
| R1-N02 | benign-near-miss | T1204 / T1059.001 | no alert | Software deployment agent runs an encoded script |
| R1-N03 | benign-near-miss | T1204 / T1059.001 | no alert | Admin runs a cradle from a terminal, not from explorer.exe |
| R1-N04 | benign-near-miss | T1204 / T1059.001 | no alert | Legacy launcher starts mshta on an intranet URL |
| R1-N05 | benign-near-miss | T1204 / T1059.001 | no alert | explorer starts PowerShell on a script file |
| R1-N06 | benign-near-miss | T1204 / T1059.001 | no alert | explorer starts PowerShell with a plain command |
| R1-N07 | benign-near-miss | T1204 / T1059.001 | no alert | URL plus the word iexplore must not count as the iex cradle |
| R1-N08 | benign-near-miss | T1218.005 | no alert | mshta on a local file |
| R1-N09 | benign-near-miss | T1204 / T1059.001 | no alert | Browser started with a URL (URL present, image not PowerShell or mshta) |
| R1-N10 | benign-near-miss | T1204 / T1059.001 | no alert | URL in a string, no download cradle |
| R1-G01 | documented-gap | T1204 / T1059.001 | no alert | cmd.exe is the child of explorer, so the PowerShell comes later with a cmd parent |
| R1-G02 | documented-gap | T1204 / T1059.001 | no alert | The PowerShell child of cmd.exe has a non-explorer parent |
| R1-G03 | documented-gap | T1204 / T1059.001 | no alert | Renamed copy of powershell.exe |
| R1-G04 | documented-gap | T1204 / T1059.001 | no alert | Truncated command line: Base64 cut below the 16-character floor |
| R1-G05 | documented-gap | T1204 / T1059.001 | no alert | Cradle assembled from string pieces defeats keyword matching |

## 4. Coverage matrix: rule 002 (non-browser credential-store read, conditional) and YARA fixtures

Rule 002 case counts by category: benign-near-miss: 10, browser-store-read: 9, documented-gap: 3, known-fp-needs-tuning: 1. Total 23.

| ID | Category | Technique | Expected | Description |
|---|---|---|---|---|
| R2-P01 | browser-store-read | T1555.003 / T1539 | alert | Unknown executable reads Chrome Login Data |
| R2-P02 | browser-store-read | T1555.003 / T1539 | alert | Unknown executable reads Chrome Network\Cookies |
| R2-P03 | browser-store-read | T1555.003 / T1539 | alert | Unknown executable reads Edge Local State (holds the key) |
| R2-P04 | browser-store-read | T1555.003 / T1539 | alert | Unknown executable reads Edge Login Data For Account |
| R2-P05 | browser-store-read | T1555.003 / T1539 | alert | Unknown executable reads Brave Web Data |
| R2-P06 | browser-store-read | T1555.003 / T1539 | alert | Unknown executable reads Firefox logins.json |
| R2-P07 | browser-store-read | T1555.003 / T1539 | alert | Unknown executable reads Firefox key4.db |
| R2-P08 | browser-store-read | T1555.003 / T1539 | alert | Unknown executable reads Firefox cookies.sqlite |
| R2-P09 | browser-store-read | T1555.003 / T1539 | alert | PowerShell reads Chrome Login Data |
| R2-N01 | benign-near-miss | T1555.003 / T1539 | no alert | Chrome (Program Files) reads its own Login Data |
| R2-N02 | benign-near-miss | T1555.003 / T1539 | no alert | Chrome (per-user install) reads its own Cookies |
| R2-N03 | benign-near-miss | T1555.003 / T1539 | no alert | Edge reads its own Cookies |
| R2-N04 | benign-near-miss | T1555.003 / T1539 | no alert | Firefox reads its own key4.db |
| R2-N05 | benign-near-miss | T1555.003 / T1539 | no alert | Chrome updater reads Local State |
| R2-N06 | benign-near-miss | T1555.003 / T1539 | no alert | Edge updater reads Local State |
| R2-N07 | benign-near-miss | T1555.003 / T1539 | no alert | Brave reads its own Web Data |
| R2-N08 | benign-near-miss | T1555.003 / T1539 | no alert | Non-browser reads a non-store file in the profile |
| R2-N09 | benign-near-miss | T1555.003 / T1539 | no alert | Non-browser reads a file named Login Data outside any profile folder |
| R2-N10 | benign-near-miss | T1555.003 / T1539 | no alert | Same as P01 but event 4656, not 4663 |
| R2-K01 | known-fp-needs-tuning | T1555.003 / T1539 | alert | Backup software reads Login Data. The rule alerts; the deployer tunes it. |
| R2-G01 | documented-gap | T1555.003 / T1539 | no alert | Stealer running inside the chrome.exe process: the process name is the browser |
| R2-G02 | documented-gap | T1555.003 / T1539 | no alert | Path-suffix spoof: a copy placed where the filter's suffix matches |
| R2-G03 | documented-gap | T1555.003 / T1539 | no alert | Opera keeps its profile outside a User Data folder |

Benign corpus: a seeded generator (`tests/fixtures/gen_benign.py`, seed 1337) builds 300 rule-001 events and 200 rule-002 events at test time. Counts are asserted. A third seeded generator builds 200 benign proxy records (seed 1339) that carry neither of rule 003's strings. Rules 001, 002 and 003 produced **0 alerts** on their corpora. These are invented corpora and **are not false-positive rates**.

### 4.2 Rule 003 (Lumma dynamic-config User-Agent strings, proxy, LOW CONFIDENCE)

**Decision.** Written on 2026-11-22 **by the repo owner**, who chose to write the rule on the two User-Agent strings ESET publishes for the dynamic-configuration request. This **replaces** the earlier decision to leave rule 003 unwritten. That earlier decision rested on my statement that no source published a C2 User-Agent, which was wrong for ESET.

**Tags.** **[V: ESET]** for the two strings. **[A]** for the rule, its POST condition and its level (`low`). Both strings were matched **exactly, once each**, against the raw ESET page text on 2026-11-22. The page contains no other User-Agent string. A test pins the rule to exactly those two strings, so no other User-Agent can be added without failing the suite.

**It is low confidence, and these limits apply (they are also in the rule header):**

1. **Legitimate traffic can use those Chrome versions.** Chrome/119 and Chrome/109 are ordinary browser builds. A real user or application that sends one of the strings and POSTs will alert. Case R3-K01 shows this: the rule alerts on it by design.
2. **Proxy logs do not record the process name.** A proxy record gives the client address, method, host and User-Agent. **The rule cannot confirm the source process.** The analyst has to find the process on the endpoint (`IR_PLAYBOOK.md`, rule 003 path).
3. **There is no local baseline of normal traffic.** `ENVIRONMENT_ASSUMPTIONS.md` has none. How often these strings appear in normal traffic is unknown, so the alert volume and false-positive rate are unknown. The 200-record benign corpus is invented and tells you nothing about this.

Also: a proxy sees a User-Agent only for plain HTTP or inspected TLS. For un-inspected HTTPS it logs a CONNECT without one, and the rule is blind (case R3-G01). `ENVIRONMENT_ASSUMPTIONS.md` says the User-Agent is logged "where available" and does not say TLS is inspected, so whether the rule can fire in the reference environment is **unknown**. The operators can also change the strings; ESET's report covers samples up to May 2025.

Coverage matrix, rule 003. Case counts by category: benign-near-miss: 2, c2-useragent: 2, documented-gap: 1, known-fp-needs-tuning: 1. Total 6. The required pair is R3-P01 (POST with a listed string, must alert) and R3-N01 (benign POST with a newer Chrome version, must not alert). The Chrome version in R3-N01 is illustrative, not a claim about the current release. R3-P02, R3-N02, R3-K01 and R3-G01 are extra cases added to cover the second string, the POST condition, the known false positive and the TLS gap.

| ID | Category | Technique | Expected | Description |
|---|---|---|---|---|
| R3-P01 | c2-useragent | T1071.001 | alert | POST with ESET's 'Old' User-Agent (Chrome/119) to a synthetic C2 host |
| R3-P02 | c2-useragent | T1071.001 | alert | POST with ESET's 'New' User-Agent (Chrome/109) to a synthetic C2 host |
| R3-N01 | benign-near-miss | T1071.001 | no alert | Benign POST with a newer Chrome version (not one of the two strings) |
| R3-N02 | benign-near-miss | T1071.001 | no alert | GET with the Chrome/119 string: the rule requires POST |
| R3-K01 | known-fp-needs-tuning | T1071.001 | alert | Legitimate user on an old Chrome/109 build POSTs a web form. The rule alerts; there is no baseline to tune against. |
| R3-G01 | documented-gap | T1071.001 | no alert | Un-inspected HTTPS: the proxy logs a CONNECT with no User-Agent, so the rule is blind |

### 4.3 YARA fixtures

YARA fixtures for `re_lumma_config_strings.yar` (rule `RE_Lumma_C2_Protocol_Strings`):

| Fixture | Expected |
|---|---|
| cfg_negative_filler | no match |
| cfg_negative_no_param | no match |
| cfg_negative_no_version | no match |
| cfg_negative_two_commands | no match |
| cfg_positive_all | match |
| cfg_positive_lid_variant | match |
| cfg_positive_uid_variant | match |

YARA fixtures for `re_lumma_chacha_setup.yar` (rule `RE_Lumma_ChaCha_WinHttp_Cooccurrence`):

| Fixture | Expected |
|---|---|
| setup_negative_constant_and_dll | no match |
| setup_negative_constant_only | no match |
| setup_negative_filler | no match |
| setup_negative_winhttp_only | no match |
| setup_positive_all | match |
| setup_positive_wide_dll | match |

## 5. Mutation results

Each mutation is applied in memory. The tests assert the exact set of cases that turn red. Section 9.2 shows the YARA mutations M5 and M6 run directly.

| # | Break | Named cases that must turn red | Result |
|---|---|---|---|
| M1 | Drop the `-enc` variant from rule 001 | R1-P01 to R1-P06 (every Base64 positive) | **Caught [V]**: exactly these six turned red. |
| M2 | Remove the parent-process filter from rule 001 | R1-N01 to R1-N04 (benign near-misses, non-explorer parent) | **Caught [V]**: those four turned red, plus documented gap R1-G02 (cmd.exe parent), which then alerts. |
| M3 | Remove the non-browser filter from rule 002 | R2-N01 to R2-N07 (browsers and updaters) | **Caught [V]**: those seven turned red, plus gaps R2-G01 and R2-G02, which then alert. |
| M4 | Change the config key length in `config_extract.py` | The ChaCha20 round-trip case | **Caught [V]**: round trip fails with `KEY_LEN = 24`. |
| M5 | Remove one indicator string (`$ver40`) from `re_lumma_config_strings.yar` | `cfg_positive_all`, `cfg_positive_lid_variant`, `cfg_positive_uid_variant` | **Caught [V]**: exactly those three turned red. **The mutated rule compiles without error.** YARA 4.5.4 only warns under `error_on_warning`: `line 48: expression always false - requesting 4 of 3.` (section 9.2). So the mutated rule is valid but can never match. |
| M6 | Weaken the setup condition from `all of them` to `any of them` | `setup_negative_constant_only`, `setup_negative_winhttp_only`, `setup_negative_constant_and_dll` | **Caught [V]**: exactly those three turned red. |
| M7 | Drop the Chrome/109 User-Agent string from rule 003 | R3-P02 (the Chrome/109 positive) | **Caught [V]**: R3-P02 turned red, plus R3-K01 (the legitimate Chrome/109 case, which the rule alerts on by design and which goes quiet when the string is dropped). The rule's POST condition has a case (R3-N02) but no mutation of its own. |

Limit of M5: it shows that the rule's strict count (`4 of` the named strings) breaks when an indicator is removed. It does not show how detection degrades when an indicator is missing from a real sample, because no real sample is used.

## 6. Baseline and real-data log

**Not yet run.** Metric targets are **not set** (blueprint section 2). They are set only after a baseline, with reasons.

| Item | Value |
|---|---|
| Benign corpus from own clean endpoints (never committed) | Not yet run |
| Rule 001 false-positive count on that corpus | Not yet run |
| Rule 002 false-positive count on that corpus | Not yet run (needs the 4663 SACL first) |
| Offline lab execution of a sample (needs authority; none assumed) | Not yet run. Not available in the reference environment. |
| Rule 001 miss rate on lab executions | Not yet run |
| YARA hit and miss on real builds | Not yet run. Rules are low confidence and untested on real samples. |
| Target: acceptable false positives per day | Not set. Needs fleet size and alert budget, which `ENVIRONMENT_ASSUMPTIONS.md` does not contain. |
| Target: minimum detection rate | Not set. |
| Last revalidation date | Never |
| Next revalidation due | Not set. `BLUEPRINT.md` suggests quarterly **[A]**; no cadence is in the assumptions. |

## 7. How to reproduce

Run from the repository root, on Python 3.12. The root [README](../README.md#run-the-tests) has the Docker command (the PowerShell form was run for this file; the POSIX form is marked not verified there) and the commands without Docker. This module's suite is:

```bash
# verified-locally: 2026-11-22, in the python:3.12 container (the same commands are tagged "verified" in the module README)
python -m pip install -r re-lumma-stealer/tests/requirements.txt
python -m pytest re-lumma-stealer/tests -q
```

Pin the image by digest (`python@sha256:5411fa1b302c43f510324381162b5f5d0d93b9ee2af538f09d944f0d290ee3cb`) if you need the same bytes again; the `python:3.12` tag moves. `re-lumma-stealer/tests/fixtures/build_cases.py` regenerates the JSONL case files, and a test checks that they are current.

## 8. Known limits

- Rule 003 is written at **low confidence** (section 4.2; decision made 2026-11-22 by the repo owner). Microsoft published no C2 User-Agent **[V: absent]**; the rule uses only the two strings ESET lists **[V: ESET]**. Legitimate traffic can use those Chrome versions, proxy logs do not record the process name so the rule cannot confirm the source process, and there is no local baseline of normal traffic. It is blind when HTTPS is not inspected.
- Rule 001 misses: PowerShell started through `cmd.exe`, renamed copies, string-assembled cradles, and truncated command lines (cases R1-G01 to R1-G05).
- Rule 002 misses: injection into a browser process, path-suffix spoofing, and browsers whose profile is not under `User Data` such as Opera (cases R2-G01 to R2-G03).
- Process hollowing, in-memory loading and C2 content need telemetry the reference environment does not assume.
- YARA rules use published strings only. Elastic reports parts of the ChaCha20 constant are decrypted at runtime and XOR-ROL derived **[V]**, so the setup rule may miss the family it names, and it will match benign programs that use ChaCha20 and WinHTTP.
- The `pe` module is not used, so no condition is untestable on synthetic filler.
- ATT&CK IDs and names were checked against the versioned v17 pages on 2026-11-22: every ID used in a rule tag, fixture label or the playbook exists in v17. The check does not show that each technique describes Lumma behaviour, and one ID named only in `CTI_CONTEXT.md` (T1685) is not found in v17 (section 8.1).
- Source claims in the docs were re-verified on 2026-11-22 against raw downloaded pages by exact string match. `iocs.csv` hashes were matched exactly, case included.

### 8.1 ATT&CK ID crosswalk check

**What was checked, and when.** On 2026-11-22, every ATT&CK technique and sub-technique ID that appears in `re-lumma-stealer` (16 IDs: in `CTI_CONTEXT.md`, the case tables here, `IR_PLAYBOOK.md`, the three Sigma rule tags and the fixture labels) was fetched from its versioned ATT&CK v17 page and from the current page (footer "ATT&CK content v20.1"), with `curl`, into a scratch directory outside the repo. Software page S1213 was fetched in both versions. For each page the check recorded the HTTP status, the name printed in the title, whether `ID: <ID>` and that name occur in the visible text, the footer version, and whether the text contains `revok` or `deprecat`. The method, the full table and the result are in `CTI_CONTEXT.md` section 3.1.

**Result.** 15 of the 16 IDs exist in v17 (footer v17.1) with the same name as in the current version. None is marked revoked or deprecated in either. **T1685 is not found in v17** (HTTP 404 on its versioned URL); it is named only in the version caveat of `CTI_CONTEXT.md` section 3, in no rule tag, fixture label, test table or playbook. Nothing was changed in any rule, test, fixture or `iocs.csv`, so no rule or fixture needs a fix because of this check.

**What this check does not show.** **The crosswalk checks IDs and names only. It does not check whether each technique really describes Lumma behaviour.** The mapping of Lumma behaviour to techniques is the analyst's own reading **[A]**. It also does not check whether AA25-141B lists each ID, and the downloaded pages are not committed, so a reader has to fetch them again to repeat it. The absence of T1685 from v17 is tagged **[U]**, because a 404 on one URL is not an exact-string find.

## 9. Real test output

All output below was produced on 2026-11-22 by the script that wrote this file, in the `python:3.12` container, with the repository mounted read-only at `/repo` and each suite started from `/repo` as CI starts it. Nothing is edited. **One exception to "the script that wrote this file":** block 9.3 was replaced by a re-run made later on 2026-11-22, in the same container and with the same mount, on the branch that added the ATT&CK crosswalk (section 8.1). The earlier 9.3 block was stale, because the cwe-078 suite had grown since it was pasted; the new block's header and summary lines show the current size. That re-run also ran this module's suite and the documentation checks. Both passed with the same totals as 9.1 and 9.4, so those two blocks are left as first pasted.

### 9.1 re-lumma-stealer suite, exit code 0

```
Python 3.12.16

--- installed:
cryptography        50.0.2
pySigma             2.1.1
pytest              9.2.0
PyYAML              6.0.4
sigma-cli           4.0.1
yara-python         4.5.4
yara.YARA_VERSION = 4.5.4

============================= test session starts ==============================
platform linux -- Python 3.12.16, pytest-9.2.0, pluggy-1.7.0 -- /usr/local/bin/python
rootdir: /repo/re-lumma-stealer
configfile: pytest.ini
collecting ... collected 175 items

re-lumma-stealer/tests/test_config_extract.py::test_cipher_known_answer_zero_key PASSED [  0%]
re-lumma-stealer/tests/test_config_extract.py::test_round_trip_recovers_synthetic_config PASSED [  1%]
re-lumma-stealer/tests/test_config_extract.py::test_blob_layout_matches_documented_offsets PASSED [  1%]
re-lumma-stealer/tests/test_config_extract.py::test_ciphertext_does_not_contain_plaintext PASSED [  2%]
re-lumma-stealer/tests/test_config_extract.py::test_blob_is_deterministic_and_seed_changes_it PASSED [  2%]
re-lumma-stealer/tests/test_config_extract.py::test_parse_returns_the_parts PASSED [  3%]
re-lumma-stealer/tests/test_config_extract.py::test_short_blob_rejected[0] PASSED [  4%]
re-lumma-stealer/tests/test_config_extract.py::test_short_blob_rejected[1] PASSED [  4%]
re-lumma-stealer/tests/test_config_extract.py::test_short_blob_rejected[59] PASSED [  5%]
re-lumma-stealer/tests/test_config_extract.py::test_wrong_magic_rejected PASSED [  5%]
re-lumma-stealer/tests/test_config_extract.py::test_real_looking_file_is_refused PASSED [  6%]
re-lumma-stealer/tests/test_config_extract.py::test_truncated_ciphertext_rejected PASSED [  6%]
re-lumma-stealer/tests/test_config_extract.py::test_oversized_length_field_rejected PASSED [  7%]
re-lumma-stealer/tests/test_config_extract.py::test_bad_key_or_nonce_length_rejected PASSED [  8%]
re-lumma-stealer/tests/test_config_extract.py::test_wrong_key_does_not_recover_config PASSED [  8%]
re-lumma-stealer/tests/test_config_extract.py::test_cli_refuses_non_synthetic_file PASSED [  9%]
re-lumma-stealer/tests/test_config_extract.py::test_cli_decrypts_synthetic_blob PASSED [  9%]
re-lumma-stealer/tests/test_mutations.py::test_baseline_unmutated_rules_have_no_red_cases PASSED [ 10%]
re-lumma-stealer/tests/test_mutations.py::test_m1_drop_encoded_variant_from_rule_001 PASSED [ 10%]
re-lumma-stealer/tests/test_mutations.py::test_m2_remove_parent_filter_from_rule_001 PASSED [ 11%]
re-lumma-stealer/tests/test_mutations.py::test_m3_remove_browser_filter_from_rule_002 PASSED [ 12%]
re-lumma-stealer/tests/test_mutations.py::test_m7_drop_the_chrome_109_user_agent_from_rule_003 PASSED [ 12%]
re-lumma-stealer/tests/test_mutations.py::test_m4_change_key_length_in_extractor PASSED [ 13%]
re-lumma-stealer/tests/test_mutations.py::test_m5_remove_one_indicator_from_config_strings_rule PASSED [ 13%]
re-lumma-stealer/tests/test_mutations.py::test_m6_weaken_setup_condition_to_any_of PASSED [ 14%]
re-lumma-stealer/tests/test_sigma_rules.py::test_pysigma_version_matches_pin PASSED [ 14%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_parses_with_pysigma_and_has_required_metadata[re_lumma_001] PASSED [ 15%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_parses_with_pysigma_and_has_required_metadata[re_lumma_002] PASSED [ 16%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_parses_with_pysigma_and_has_required_metadata[re_lumma_003] PASSED [ 16%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_ids_are_unique PASSED [ 17%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_002_declares_that_it_cannot_fire_in_the_reference_environment PASSED [ 17%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_003_contains_exactly_the_two_eset_user_agents PASSED [ 18%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_003_header_states_tags_confidence_and_the_three_limits PASSED [ 18%]
re-lumma-stealer/tests/test_sigma_rules.py::test_committed_case_files_match_the_builder PASSED [ 19%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P01] PASSED [ 20%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P02] PASSED [ 20%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P03] PASSED [ 21%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P04] PASSED [ 21%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P05] PASSED [ 22%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P06] PASSED [ 22%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P07] PASSED [ 23%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P08] PASSED [ 24%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P09] PASSED [ 24%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P10] PASSED [ 25%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N01] PASSED [ 25%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N02] PASSED [ 26%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N03] PASSED [ 26%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N04] PASSED [ 27%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N05] PASSED [ 28%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N06] PASSED [ 28%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N07] PASSED [ 29%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N08] PASSED [ 29%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N09] PASSED [ 30%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N10] PASSED [ 30%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-G01] PASSED [ 31%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-G02] PASSED [ 32%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-G03] PASSED [ 32%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-G04] PASSED [ 33%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-G05] PASSED [ 33%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P01] PASSED [ 34%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P02] PASSED [ 34%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P03] PASSED [ 35%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P04] PASSED [ 36%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P05] PASSED [ 36%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P06] PASSED [ 37%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P07] PASSED [ 37%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P08] PASSED [ 38%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P09] PASSED [ 38%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N01] PASSED [ 39%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N02] PASSED [ 40%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N03] PASSED [ 40%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N04] PASSED [ 41%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N05] PASSED [ 41%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N06] PASSED [ 42%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N07] PASSED [ 42%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N08] PASSED [ 43%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N09] PASSED [ 44%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N10] PASSED [ 44%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-K01] PASSED [ 45%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-G01] PASSED [ 45%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-G02] PASSED [ 46%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-G03] PASSED [ 46%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R3-P01] PASSED [ 47%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R3-P02] PASSED [ 48%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R3-N01] PASSED [ 48%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R3-N02] PASSED [ 49%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R3-K01] PASSED [ 49%]
re-lumma-stealer/tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R3-G01] PASSED [ 50%]
re-lumma-stealer/tests/test_sigma_rules.py::test_required_categories_and_tp_and_benign_present[re_lumma_001] PASSED [ 50%]
re-lumma-stealer/tests/test_sigma_rules.py::test_required_categories_and_tp_and_benign_present[re_lumma_002] PASSED [ 51%]
re-lumma-stealer/tests/test_sigma_rules.py::test_required_categories_and_tp_and_benign_present[re_lumma_003] PASSED [ 52%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-P01] PASSED [ 52%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-P02] PASSED [ 53%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-P03] PASSED [ 53%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-P04] PASSED [ 54%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-P05] PASSED [ 54%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-P06] PASSED [ 55%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-P07] PASSED [ 56%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-P08] PASSED [ 56%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-P09] PASSED [ 57%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-P10] PASSED [ 57%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-N01] PASSED [ 58%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-N02] PASSED [ 58%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-N03] PASSED [ 59%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-N04] PASSED [ 60%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-N05] PASSED [ 60%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-N06] PASSED [ 61%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-N07] PASSED [ 61%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-N08] PASSED [ 62%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-N09] PASSED [ 62%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-N10] PASSED [ 63%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-G01] PASSED [ 64%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-G02] PASSED [ 64%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-G03] PASSED [ 65%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-G04] PASSED [ 65%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R1-G05] PASSED [ 66%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R2-P01] PASSED [ 66%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R2-P02] PASSED [ 67%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R2-P03] PASSED [ 68%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R2-P04] PASSED [ 68%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R2-P05] PASSED [ 69%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R2-P06] PASSED [ 69%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R2-P07] PASSED [ 70%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R2-P08] PASSED [ 70%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R2-P09] PASSED [ 71%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R2-N01] PASSED [ 72%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R2-N02] PASSED [ 72%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R2-N03] PASSED [ 73%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R2-N04] PASSED [ 73%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R2-N05] PASSED [ 74%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R2-N06] PASSED [ 74%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R2-N07] PASSED [ 75%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R2-N08] PASSED [ 76%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R2-N09] PASSED [ 76%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R2-N10] PASSED [ 77%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R2-K01] PASSED [ 77%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R2-G01] PASSED [ 78%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R2-G02] PASSED [ 78%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R2-G03] PASSED [ 79%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R3-P01] PASSED [ 80%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R3-P02] PASSED [ 80%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R3-N01] PASSED [ 81%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R3-N02] PASSED [ 81%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R3-K01] PASSED [ 82%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_against_case[R3-G01] PASSED [ 82%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_does_not_fire_on_the_other_rules_events[re_lumma_001] PASSED [ 83%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_does_not_fire_on_the_other_rules_events[re_lumma_002] PASSED [ 84%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_does_not_fire_on_the_other_rules_events[re_lumma_003] PASSED [ 84%]
re-lumma-stealer/tests/test_sigma_rules.py::test_benign_corpus_counts_are_fixed PASSED [ 85%]
re-lumma-stealer/tests/test_sigma_rules.py::test_benign_corpus_is_deterministic PASSED [ 85%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_001_silent_on_synthetic_benign_corpus PASSED [ 86%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_002_silent_on_synthetic_benign_corpus PASSED [ 86%]
re-lumma-stealer/tests/test_sigma_rules.py::test_rule_003_silent_on_synthetic_benign_proxy_corpus PASSED [ 87%]
re-lumma-stealer/tests/test_yara_rules.py::test_yara_python_version_matches_pin PASSED [ 88%]
re-lumma-stealer/tests/test_yara_rules.py::test_rule_file_compiles_without_warnings_and_declares_its_basis[re_lumma_config_strings.yar] PASSED [ 88%]
re-lumma-stealer/tests/test_yara_rules.py::test_rule_file_compiles_without_warnings_and_declares_its_basis[re_lumma_chacha_setup.yar] PASSED [ 89%]
re-lumma-stealer/tests/test_yara_rules.py::test_rules_do_not_use_pe_module[re_lumma_config_strings.yar] PASSED [ 89%]
re-lumma-stealer/tests/test_yara_rules.py::test_rules_do_not_use_pe_module[re_lumma_chacha_setup.yar] PASSED [ 90%]
re-lumma-stealer/tests/test_yara_rules.py::test_fixtures_are_non_executable PASSED [ 90%]
re-lumma-stealer/tests/test_yara_rules.py::test_config_strings_rule_against_fixture[cfg_negative_filler] PASSED [ 91%]
re-lumma-stealer/tests/test_yara_rules.py::test_config_strings_rule_against_fixture[cfg_negative_no_param] PASSED [ 92%]
re-lumma-stealer/tests/test_yara_rules.py::test_config_strings_rule_against_fixture[cfg_negative_no_version] PASSED [ 92%]
re-lumma-stealer/tests/test_yara_rules.py::test_config_strings_rule_against_fixture[cfg_negative_two_commands] PASSED [ 93%]
re-lumma-stealer/tests/test_yara_rules.py::test_config_strings_rule_against_fixture[cfg_positive_all] PASSED [ 93%]
re-lumma-stealer/tests/test_yara_rules.py::test_config_strings_rule_against_fixture[cfg_positive_lid_variant] PASSED [ 94%]
re-lumma-stealer/tests/test_yara_rules.py::test_config_strings_rule_against_fixture[cfg_positive_uid_variant] PASSED [ 94%]
re-lumma-stealer/tests/test_yara_rules.py::test_setup_rule_against_fixture[setup_negative_constant_and_dll] PASSED [ 95%]
re-lumma-stealer/tests/test_yara_rules.py::test_setup_rule_against_fixture[setup_negative_constant_only] PASSED [ 96%]
re-lumma-stealer/tests/test_yara_rules.py::test_setup_rule_against_fixture[setup_negative_filler] PASSED [ 96%]
re-lumma-stealer/tests/test_yara_rules.py::test_setup_rule_against_fixture[setup_negative_winhttp_only] PASSED [ 97%]
re-lumma-stealer/tests/test_yara_rules.py::test_setup_rule_against_fixture[setup_positive_all] PASSED [ 97%]
re-lumma-stealer/tests/test_yara_rules.py::test_setup_rule_against_fixture[setup_positive_wide_dll] PASSED [ 98%]
re-lumma-stealer/tests/test_yara_rules.py::test_each_rule_ignores_the_other_rules_positives PASSED [ 98%]
re-lumma-stealer/tests/test_yara_rules.py::test_rules_ignore_the_synthetic_config_blob PASSED [ 99%]
re-lumma-stealer/tests/test_yara_rules.py::test_fixture_sets_are_deterministic PASSED [100%]

============================= 175 passed in 1.36s ==============================
```

### 9.2 M5 and M6 run directly (compile result, warnings, per-fixture matches), exit code 0

```
yara 4.5.4

=== config_strings ORIGINAL
compile (error_on_warning=False): OK
compile (error_on_warning=True): OK
  cfg_negative_filler                  expected=False matched=False
  cfg_negative_no_param                expected=False matched=False
  cfg_negative_no_version              expected=False matched=False
  cfg_negative_two_commands            expected=False matched=False
  cfg_positive_all                     expected=True  matched=True 
  cfg_positive_lid_variant             expected=True  matched=True 
  cfg_positive_uid_variant             expected=True  matched=True 

=== M5 mutated config_strings (string removed, condition '4 of ($cmd_*)')
compile (error_on_warning=False): OK
compile (error_on_warning=True): WarningError: ['line 48: expression always false - requesting 4 of 3.']
  cfg_negative_filler                  expected=False matched=False
  cfg_negative_no_param                expected=False matched=False
  cfg_negative_no_version              expected=False matched=False
  cfg_negative_two_commands            expected=False matched=False
  cfg_positive_all                     expected=True  matched=False   <-- RED (differs from expected)
  cfg_positive_lid_variant             expected=True  matched=False   <-- RED (differs from expected)
  cfg_positive_uid_variant             expected=True  matched=False   <-- RED (differs from expected)

=== setup ORIGINAL
compile (error_on_warning=False): OK
compile (error_on_warning=True): OK
  setup_negative_constant_and_dll      expected=False matched=False
  setup_negative_constant_only         expected=False matched=False
  setup_negative_filler                expected=False matched=False
  setup_negative_winhttp_only          expected=False matched=False
  setup_positive_all                   expected=True  matched=True 
  setup_positive_wide_dll              expected=True  matched=True 

=== M6 mutated setup ('any of them')
compile (error_on_warning=False): OK
compile (error_on_warning=True): OK
  setup_negative_constant_and_dll      expected=False matched=True    <-- RED (differs from expected)
  setup_negative_constant_only         expected=False matched=True    <-- RED (differs from expected)
  setup_negative_filler                expected=False matched=False
  setup_negative_winhttp_only          expected=False matched=True    <-- RED (differs from expected)
  setup_positive_all                   expected=True  matched=True 
  setup_positive_wide_dll              expected=True  matched=True 

M5 mutated condition lines:
        $cmd_recv = "receive_message" ascii wide
        $cmd_send = "send_message" ascii wide
        $cmd_get  = "get_message" ascii wide
        4 of ($cmd_*) and
        1 of ($p_*)
```

### 9.3 cwe-078-os-command-injection suite, exit code 0

```
============================= test session starts ==============================
platform linux -- Python 3.12.16, pytest-9.2.0, pluggy-1.7.0 -- /usr/local/bin/python
rootdir: /repo/cwe-078-os-command-injection
configfile: pytest.ini
collecting ... collected 61 items

cwe-078-os-command-injection/tests/test_gap_cases.py::test_adding_the_missing_pattern_flips_only_that_gap_case[B-09] PASSED [  1%]
cwe-078-os-command-injection/tests/test_gap_cases.py::test_adding_the_missing_pattern_flips_only_that_gap_case[B-10] PASSED [  3%]
cwe-078-os-command-injection/tests/test_gap_cases.py::test_adding_the_missing_pattern_flips_only_that_gap_case[B-11] PASSED [  4%]
cwe-078-os-command-injection/tests/test_gap_cases.py::test_adding_the_missing_pattern_flips_only_that_gap_case[B-12] PASSED [  6%]
cwe-078-os-command-injection/tests/test_gap_cases.py::test_adding_the_missing_pattern_flips_only_that_gap_case[B-13] PASSED [  8%]
cwe-078-os-command-injection/tests/test_gap_cases.py::test_adding_the_missing_pattern_flips_only_that_gap_case[B-14] PASSED [  9%]
cwe-078-os-command-injection/tests/test_gap_cases.py::test_adding_the_missing_pattern_flips_only_that_gap_case[B-15] PASSED [ 11%]
cwe-078-os-command-injection/tests/test_gap_cases.py::test_every_documented_gap_case_has_a_sensitivity_test_or_is_the_older_scope_gap PASSED [ 13%]
cwe-078-os-command-injection/tests/test_gap_cases.py::test_tuning_away_the_known_false_positive_also_silences_real_semicolon_injections PASSED [ 14%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[TP-01] PASSED [ 16%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[TP-02] PASSED [ 18%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[TP-03] PASSED [ 19%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[TP-04] PASSED [ 21%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[TP-05] PASSED [ 22%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[TP-06] PASSED [ 24%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[TP-07] PASSED [ 26%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[TP-08] PASSED [ 27%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[TP-09] PASSED [ 29%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[TP-10] PASSED [ 31%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[TP-11] PASSED [ 32%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[TP-12] PASSED [ 34%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[TP-13] PASSED [ 36%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[TP-14] PASSED [ 37%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[TP-15] PASSED [ 39%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[TP-16] PASSED [ 40%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[B-01] PASSED  [ 42%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[B-02] PASSED  [ 44%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[B-03] PASSED  [ 45%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[B-04] PASSED  [ 47%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[B-05] PASSED  [ 49%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[B-06] PASSED  [ 50%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[B-07] PASSED  [ 52%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[B-08] PASSED  [ 54%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[B-09] PASSED  [ 55%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[B-10] PASSED  [ 57%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[B-11] PASSED  [ 59%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[B-12] PASSED  [ 60%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[B-13] PASSED  [ 62%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[B-14] PASSED  [ 63%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[B-15] PASSED  [ 65%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[B-16] PASSED  [ 67%]
cwe-078-os-command-injection/tests/test_rule.py::test_corpus_has_the_expected_number_of_unique_cases PASSED [ 68%]
cwe-078-os-command-injection/tests/test_rule.py::test_documented_gap_cases_are_not_alerts_and_say_what_they_are PASSED [ 70%]
cwe-078-os-command-injection/tests/test_rule.py::test_known_false_positive_cases_alert_and_say_how_to_tune PASSED [ 72%]
cwe-078-os-command-injection/tests/test_rule.py::test_rule_header_points_to_every_gap_and_false_positive_case_and_labels_the_placeholder PASSED [ 73%]
cwe-078-os-command-injection/tests/test_rule.py::test_all_three_log_formats_are_exercised PASSED [ 75%]
cwe-078-os-command-injection/tests/test_rule.py::test_required_category_is_covered[authorized_scanner-1] PASSED [ 77%]
cwe-078-os-command-injection/tests/test_rule.py::test_required_category_is_covered[documented_gap-8] PASSED [ 78%]
cwe-078-os-command-injection/tests/test_rule.py::test_required_category_is_covered[double_url_encoded-2] PASSED [ 80%]
cwe-078-os-command-injection/tests/test_rule.py::test_required_category_is_covered[evasion-2] PASSED [ 81%]
cwe-078-os-command-injection/tests/test_rule.py::test_required_category_is_covered[known_fp_needs_tuning-1] PASSED [ 83%]
cwe-078-os-command-injection/tests/test_rule.py::test_required_category_is_covered[legitimate_traffic-3] PASSED [ 85%]
cwe-078-os-command-injection/tests/test_rule.py::test_required_category_is_covered[param_scope-2] PASSED [ 86%]
cwe-078-os-command-injection/tests/test_rule.py::test_required_category_is_covered[raw_ampersand_split-2] PASSED [ 88%]
cwe-078-os-command-injection/tests/test_rule.py::test_required_category_is_covered[raw_payload-4] PASSED [ 90%]
cwe-078-os-command-injection/tests/test_rule.py::test_required_category_is_covered[scanner_filter_scope-1] PASSED [ 91%]
cwe-078-os-command-injection/tests/test_rule.py::test_required_category_is_covered[single_url_encoded-4] PASSED [ 93%]
cwe-078-os-command-injection/tests/test_rule.py::test_required_category_is_covered[unrelated_endpoint-1] PASSED [ 95%]
cwe-078-os-command-injection/tests/test_rule.py::test_rule_metadata_is_production_shaped PASSED [ 96%]
cwe-078-os-command-injection/tests/test_rule.py::test_testing_md_lists_every_case_and_the_rule_id PASSED [ 98%]
cwe-078-os-command-injection/tests/test_rule.py::test_evaluator_fails_loudly_on_unsupported_syntax PASSED [100%]
==================== Detection test matrix: cmdi_sigma.yml =====================

ID     RESULT  EXPECTED  FORMAT                 CATEGORY               TECHNIQUE
B-01   PASS    no alert  nginx_combined         legitimate_traffic     legit_ping_param_ip
B-02   PASS    no alert  apache_vhost_combined  legitimate_traffic     legit_host_with_count
B-03   PASS    no alert  iis_w3c                legitimate_traffic     legit_health_check_no_query
B-04   PASS    no alert  nginx_combined         raw_ampersand_split    raw_double_ampersand_path_scope
B-05   PASS    no alert  apache_vhost_combined  raw_ampersand_split    raw_double_ampersand_param_scope
B-06   PASS    no alert  nginx_combined         authorized_scanner     authorized_scanner_range
B-07   PASS    no alert  iis_w3c                unrelated_endpoint     path_ends_in_ping_not_endpoint
B-08   PASS    no alert  apache_vhost_combined  documented_gap         other_path_other_param_name
B-09   PASS    no alert  nginx_combined         documented_gap         triple_encoded_semicolon
B-10   PASS    no alert  apache_vhost_combined  documented_gap         fullwidth_semicolon_literal
B-11   PASS    no alert  iis_w3c                documented_gap         fullwidth_semicolon_percent_encoded
B-12   PASS    no alert  nginx_combined         documented_gap         overlong_utf8_slash
B-13   PASS    no alert  apache_vhost_combined  documented_gap         tab_whitespace
B-14   PASS    no alert  iis_w3c                documented_gap         null_byte
B-15   PASS    no alert  nginx_combined         documented_gap         other_path_ping_php
B-16   PASS    alert     apache_vhost_combined  known_fp_needs_tuning  legit_multi_target_semicolon_list
TP-01  PASS    alert     nginx_combined         raw_payload            raw_semicolon
TP-02  PASS    alert     apache_vhost_combined  raw_payload            raw_pipe
TP-03  PASS    alert     nginx_combined         raw_payload            raw_command_substitution
TP-04  PASS    alert     apache_vhost_combined  raw_payload            raw_backtick
TP-05  PASS    alert     iis_w3c                single_url_encoded     encoded_semicolon_upper_hex
TP-06  PASS    alert     nginx_combined         single_url_encoded     encoded_pipe_lower_hex
TP-07  PASS    alert     apache_vhost_combined  single_url_encoded     encoded_double_ampersand
TP-08  PASS    alert     iis_w3c                single_url_encoded     encoded_newline
TP-09  PASS    alert     nginx_combined         single_url_encoded     encoded_command_substitution
TP-10  PASS    alert     apache_vhost_combined  double_url_encoded     double_encoded_semicolon
TP-11  PASS    alert     iis_w3c                double_url_encoded     double_encoded_pipe
TP-12  PASS    alert     nginx_combined         evasion                ifs_space_substitution_raw
TP-13  PASS    alert     apache_vhost_combined  evasion                ifs_space_substitution_encoded_isolated
TP-14  PASS    alert     nginx_combined         param_scope            ping_param_other_path_raw
TP-15  PASS    alert     iis_w3c                param_scope            ping_param_not_first_encoded
TP-16  PASS    alert     nginx_combined         scanner_filter_scope   non_allowlisted_source_same_payload_as_B06

32/32 cases PASS
============================== 61 passed in 0.41s ==============================
```

### 9.4 docs-checks suite, exit code 0

This runs the documentation checks over the whole repository and, in the same run, every mutation proof.

```
============================= test session starts ==============================
platform linux -- Python 3.12.16, pytest-9.2.0, pluggy-1.7.0 -- /usr/local/bin/python
rootdir: /repo/docs-checks
configfile: pytest.ini
collecting ... collected 72 items

docs-checks/tests/test_docs_checks.py::test_links_and_anchors_resolve PASSED [  1%]
docs-checks/tests/test_docs_checks.py::test_quoted_counts_match_what_pytest_collects PASSED [  2%]
docs-checks/tests/test_docs_checks.py::test_every_command_block_is_tagged PASSED [  4%]
docs-checks/tests/test_docs_checks.py::test_verified_commands_run_and_exit_zero PASSED [  5%]
docs-checks/tests/test_docs_checks.py::test_module_table_matches_folders_and_required_files PASSED [  6%]
docs-checks/tests/test_docs_checks.py::test_sigma_rule_files_have_required_fields_and_limits_header PASSED [  8%]
docs-checks/tests/test_docs_checks.py::test_yara_rule_files_have_required_meta_and_header PASSED [  9%]
docs-checks/tests/test_docs_checks.py::test_rule_ids_and_names_are_unique_across_modules PASSED [ 11%]
docs-checks/tests/test_docs_checks.py::test_no_executable_headers_anywhere PASSED [ 12%]
docs-checks/tests/test_docs_checks.py::test_no_file_over_the_size_limit PASSED [ 13%]
docs-checks/tests/test_docs_checks.py::test_no_real_network_indicators_in_docs_and_fixtures PASSED [ 15%]
docs-checks/tests/test_docs_checks.py::test_no_placeholders_left_in_docs PASSED [ 16%]
docs-checks/tests/test_docs_checks.py::test_intake_rulebook_in_repo_is_an_unfilled_template PASSED [ 18%]
docs-checks/tests/test_docs_checks.py::test_checks_look_at_something PASSED [ 19%]
docs-checks/tests/test_docs_checks.py::test_version_strings_are_not_mistaken_for_ip_addresses PASSED [ 20%]
docs-checks/tests/test_docs_checks.py::test_intake_allows_a_fixed_answer_to_change[A1] PASSED [ 22%]
docs-checks/tests/test_docs_checks.py::test_intake_allows_a_fixed_answer_to_change[A2] PASSED [ 23%]
docs-checks/tests/test_docs_checks.py::test_intake_allows_a_fixed_answer_to_change[A4] PASSED [ 25%]
docs-checks/tests/test_docs_checks.py::test_intake_allows_a_fixed_answer_to_change[A5] PASSED [ 26%]
docs-checks/tests/test_docs_checks.py::test_intake_allows_a_fixed_answer_to_change[E1] PASSED [ 27%]
docs-checks/tests/test_docs_checks.py::test_intake_allows_a_fixed_answer_to_change[E2] PASSED [ 29%]
docs-checks/tests/test_docs_checks.py::test_intake_allows_a_fixed_answer_to_change[E3] PASSED [ 30%]
docs-checks/tests/test_docs_checks.py::test_intake_allows_a_fixed_answer_to_change[E4] PASSED [ 31%]
docs-checks/tests/test_docs_checks.py::test_intake_allows_a_fixed_answer_to_change[G1] PASSED [ 33%]
docs-checks/tests/test_docs_checks.py::test_intake_allows_a_fixed_answer_to_change[H1] PASSED [ 34%]
docs-checks/tests/test_docs_checks.py::test_intake_allows_a_fixed_answer_to_change[H2] PASSED [ 36%]
docs-checks/tests/test_docs_checks.py::test_intake_allows_a_fixed_answer_to_change[H3] PASSED [ 37%]
docs-checks/tests/test_docs_checks.py::test_intake_accepts_placeholders_with_or_without_backticks PASSED [ 38%]
docs-checks/tests/test_docs_checks.py::test_intake_fixed_and_required_lists_do_not_overlap_and_cover_the_expected_fields PASSED [ 40%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[links: link to a file that does not exist] PASSED [ 41%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[links: anchor that matches no heading] PASSED [ 43%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[links: link that leaves the repository] PASSED [ 44%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[numbers: test count quoted wrongly in the module table] PASSED [ 45%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[numbers: Sigma rule count quoted wrongly] PASSED [ 47%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[numbers: number written as a word is checked too] PASSED [ 48%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[numbers: bare number in root prose has no module context] PASSED [ 50%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[command-tags: command block loses its tag] PASSED [ 51%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[command-run: verified command exits non-zero] PASSED [ 52%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[command-run: verified block that would run docs-checks is refused] PASSED [ 54%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[module-table: module folder missing from the table] PASSED [ 55%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[module-table: table row for a folder that does not exist] PASSED [ 56%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[module-table: module without TESTING.md] PASSED [ 58%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[module-table: module without a tests/ directory] PASSED [ 59%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[sigma-rules: falsepositives removed] PASSED [ 61%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[sigma-rules: limits header removed] PASSED [ 62%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[sigma-rules: invalid level] PASSED [ 63%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[sigma-rules: id that is not a UUID] PASSED [ 65%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[sigma-rules: status removed] PASSED [ 66%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[yara-rules: confidence meta removed] PASSED [ 68%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[yara-rules: header comment removed] PASSED [ 69%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[rule-ids-unique: same Sigma id in a second file] PASSED [ 70%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[rule-ids-unique: same YARA rule name in a second file] PASSED [ 72%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[exec-headers: PE header in a fixture] PASSED [ 73%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[exec-headers: ELF header in a fixture] PASSED [ 75%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[file-size: file over the size limit] PASSED [ 76%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[network-indicators: real IP address in a doc] PASSED [ 77%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[network-indicators: defanged real IP address is still caught] PASSED [ 79%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[network-indicators: real domain in a doc] PASSED [ 80%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[network-indicators: defanged real domain is still caught] PASSED [ 81%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[network-indicators: real IP address in a fixture] PASSED [ 83%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[network-indicators: real domain in iocs.csv] PASSED [ 84%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[placeholders: placeholder marker left in a README] PASSED [ 86%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[placeholders: placeholder marker left in an issue template] PASSED [ 87%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[intake: a SIEM filled into field B1] PASSED [ 88%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[intake: a value filled into field G3] PASSED [ 90%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[intake: an answer filled into A3 (a placeholder field)] PASSED [ 91%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[intake: a value in a field outside both lists] PASSED [ 93%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[intake: required field deleted] PASSED [ 94%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[intake: required A3 deleted] PASSED [ 95%]
docs-checks/tests/test_docs_mutations.py::test_mutation_turns_the_check_red[intake: rulebook missing from the repository] PASSED [ 97%]
docs-checks/tests/test_docs_mutations.py::test_every_check_has_a_mutation PASSED [ 98%]
docs-checks/tests/test_docs_mutations.py::test_mutations_never_write_to_the_snapshot PASSED [100%]

============================= 72 passed in 21.71s ==============================
```
