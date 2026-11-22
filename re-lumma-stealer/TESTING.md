# Testing: re-lumma-stealer

**Last updated:** 2026-11-22. **Overall status: roadmap steps 6 and 7 are NOT complete.** The YARA rules have not been compiled or tested, because `yara-python` could not be installed on the machine used (see section 1). Nothing below claims a YARA rule works.

Tags follow `CTI_CONTEXT.md`: **[V]** verified by a run shown below, **[A]** analyst-derived, **[ASSUMED]** from `ENVIRONMENT_ASSUMPTIONS.md`.

## 0. Roadmap status

| Step | Pass condition | Status |
|---|---|---|
| 2. CTI_CONTEXT.md, ANALYSIS.md | Every claim tagged V or U. Hash only for samples. | Written. Claims tagged. No pytest applies. |
| 3. Sigma rules | Each rule has `falsepositives` and a source-limits note. | Rules 001 and 002 written, parse in pySigma, and pass their cases (section 4). **Rule 003 deliberately not written** (decision by the repo owner; see `ANALYSIS.md` section 4.1). |
| 4. YARA rules | Own patterns from own analysis. | **Written, NOT compiled, NOT tested.** No own analysis exists (no samples, `ENVIRONMENT_ASSUMPTIONS.md` section 3), so the patterns are published strings, tagged low-confidence **[A]**. |
| 5. IR_PLAYBOOK.md, iocs.csv | All indicators defanged. | Written. 9 hashes plus 2 synthetic defanged rows. Playbook is **unreviewed**. |
| 6. Fixtures and pytest suite | Suite runs, ChaCha20 round trip passes. | **Partly met.** Sigma and extractor suites pass (127 tests). YARA suite **has not run**. |
| 7. Mutation run | Every break turns its named cases red. | **Partly met.** M1 to M4 caught. **M5 and M6 have not run** (need yara-python). |
| 8. TESTING.md with baseline | Baseline recorded. | This file. **Baseline not yet run** (section 6). |
| 9. CI change | Not started. Waiting for confirmation of earlier steps. | Not done. |

## 1. Environment of the runs below

| Item | Value |
|---|---|
| Python | 3.14.4 (Windows 11). CI uses Python 3.12. |
| pySigma | 2.1.1 (pinned in `tests/requirements.txt`, asserted by a test) |
| PyYAML | 6.0.4 |
| cryptography | 50.0.2 |
| pytest | 9.2.0 |
| yara-python | NOT INSTALLED (no Windows wheel for Python 3.14) |

`yara-python` 4.5.4 has no Windows wheel for Python 3.14, and no C++ build toolchain is installed, so it could not be built locally. The YARA tests (`tests/test_yara_rules.py`) and mutations M5 and M6 need Python 3.12 (a container or CI). Docker Desktop was installed but its daemon was not running during this work. **Run section 7's commands on Python 3.12 and replace the "not run" entries before relying on any YARA result.**

## 2. What the tests do and do not show

- Sigma rules are evaluated by `tests/sigma_eval.py`, a small Sigma subset that raises on any syntax it does not know. Each rule is also parsed by pySigma. **No pySigma backend conversion was tested**, because no SIEM or backend is assumed (`ENVIRONMENT_ASSUMPTIONS.md` section 1).
- Cases are synthetic Windows event XML in the shape Windows writes for Sysmon 1 and Security 4663. No real log is used.
- A pass shows the rule logic matches the labelled cases. **It is not a detection rate or a false-positive rate.**
- Rule 002 needs a 4663 SACL that the reference environment does not enable. Its cases prove logic only. **In the reference environment the rule cannot fire.**
- The config extractor parses **our own** blob schema (`ANALYSIS.md` section 3.3). The round trip shows the parser matches that schema. It says nothing about real Lumma configs. Only the sizes of magic (16), key (32) and nonce (8) are published **[V: eSentire]**.
- The ChaCha20 call is checked against a zero-key, zero-nonce keystream vector (`test_cipher_known_answer_zero_key`). That test passed in the run below **[V]**. The vector's attribution to a published test-vector set is **not** verified from a fetched source **[U]**; the test only shows the cryptography library produces that value.

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

## 4. Coverage matrix: rule 002 (non-browser credential-store read, conditional)

Case counts by category: benign-near-miss: 10, browser-store-read: 9, documented-gap: 3, known-fp-needs-tuning: 1. Total 23.

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

Benign corpus: a seeded generator (`tests/fixtures/gen_benign.py`, seed 1337) builds 300 rule-001 events and 200 rule-002 events at test time. Counts are asserted. Both rules produced **0 alerts** on it. This is an invented corpus and **is not a false-positive rate**.

## 5. Mutation results

Each mutation is applied in memory. The test asserts the exact set of cases that turn red.

| # | Break | Named cases that must turn red | Result |
|---|---|---|---|
| M1 | Drop the `-enc` variant from rule 001 | R1-P01 to R1-P06 (every Base64 positive) | **Caught [V]**: exactly these six turned red. |
| M2 | Remove the parent-process filter from rule 001 | R1-N01 to R1-N04 (benign near-misses, non-explorer parent) | **Caught [V]**: those four turned red, plus documented gap R1-G02 (cmd.exe parent), which then alerts. |
| M3 | Remove the non-browser filter from rule 002 | R2-N01 to R2-N07 (browsers and updaters) | **Caught [V]**: those seven turned red, plus gaps R2-G01 and R2-G02, which then alert. |
| M4 | Change the config key length in `config_extract.py` | The ChaCha20 round-trip case | **Caught [V]**: round trip fails with `KEY_LEN = 24`. |
| M5 | Remove one indicator string from `re_lumma_config_strings.yar` | `cfg_positive_all` and the two variant positives | **NOT RUN.** `yara-python` unavailable. |
| M6 | Weaken the setup condition from all-of to any-of | `setup_negative_constant_only`, `setup_negative_winhttp_only`, `setup_negative_constant_and_dll` | **NOT RUN.** `yara-python` unavailable. |

M5 and M6 also have an open question: the M5 mutation leaves a condition of `4 of ($cmd_*)` over three strings. Whether YARA compiles that is **not yet known**. The test fails loudly if it does not compile.

## 6. Baseline and real-data log

**Not yet run.** Metric targets are **not set** (blueprint section 2). They are set only after a baseline, with reasons.

| Item | Value |
|---|---|
| Benign corpus from own clean endpoints (never committed) | Not yet run |
| Rule 001 false-positive count on that corpus | Not yet run |
| Rule 002 false-positive count on that corpus | Not yet run (needs the 4663 SACL first) |
| Offline lab execution of a sample (needs authority; none assumed) | Not yet run. Not available in the reference environment. |
| Rule 001 miss rate on lab executions | Not yet run |
| YARA hit and miss on real builds | Not yet run. Rules are low-confidence and untested on real samples. |
| Target: acceptable false positives per day | Not set. Needs fleet size and alert budget, which `ENVIRONMENT_ASSUMPTIONS.md` does not contain. |
| Target: minimum detection rate | Not set. |
| Last revalidation date | Never |
| Next revalidation due | Not set. `BLUEPRINT.md` suggests quarterly **[A]**; no cadence is in the assumptions. |

## 7. How to reproduce

```
python -m pip install -r tests/requirements.txt      # Python 3.12 for the YARA tests
python tests/fixtures/build_cases.py                 # regenerates the JSONL (a test checks it is current)
python -m pytest tests -v
```

## 8. Known limits

- Rule 003 (C2 POST from a non-browser) is not written. Microsoft published no C2 User-Agent **[V: absent]**. ESET lists two Chrome-looking User-Agent strings for dynamic-config requests **[V: ESET]**, which would need a baseline of legitimate Chrome versions that the reference lab lacks. Proxy logs also lack the process name. The skip decision was first made on the wrong premise that no User-Agent was published; it should be reconfirmed.
- Rule 001 misses: PowerShell started through `cmd.exe`, renamed copies, string-assembled cradles, and truncated command lines (cases R1-G01 to R1-G05).
- Rule 002 misses: injection into a browser process, path-suffix spoofing, and browsers whose profile is not under `User Data` such as Opera (cases R2-G01 to R2-G03).
- Process hollowing, in-memory loading and C2 content need telemetry the reference environment does not assume.
- YARA rules use published strings only. Elastic reports the ChaCha20 constant is decrypted at runtime **[V]**, so the setup rule may miss the family it names, and it will match benign programs that use ChaCha20 and WinHTTP.
- The `pe` module is not used, so no condition is untestable on synthetic filler.
- ATT&CK IDs are confirmed as listed on the MITRE S1213 page (footer v20.1) and, for some, in AA25-141B (v17), but are not checked against the v17 matrix (`CTI_CONTEXT.md` section 3).
- Source claims in the docs were re-verified on 2026-11-22 against raw downloaded pages by exact string match. `iocs.csv` hashes were matched exactly, case included.

## 9. Real pytest output

All output below is copied from the runs made on 2026-11-22 by the script that produced this file. Nothing is edited.

### 9.1 Sigma and extractor suites (exit code 0)

```
============================= test session starts =============================
platform win32 -- Python 3.14.4, pytest-9.2.0, pluggy-1.7.0 -- C:\Users\Kevin\AppData\Local\Temp\claude\08b1cbd4ca292511\c6160613-be43-4100-835d-e20fda17383f\scratchpad\venv\Scripts\python.exe
rootdir: X:\Defensive-Engineering-Lab\re-lumma-stealer
configfile: pytest.ini
collecting ... collected 127 items

tests/test_sigma_rules.py::test_pysigma_version_matches_pin PASSED       [  0%]
tests/test_sigma_rules.py::test_rule_parses_with_pysigma_and_has_required_metadata[re_lumma_001] PASSED [  1%]
tests/test_sigma_rules.py::test_rule_parses_with_pysigma_and_has_required_metadata[re_lumma_002] PASSED [  2%]
tests/test_sigma_rules.py::test_rule_ids_are_unique PASSED               [  3%]
tests/test_sigma_rules.py::test_rule_002_declares_that_it_cannot_fire_in_the_reference_environment PASSED [  3%]
tests/test_sigma_rules.py::test_committed_case_files_match_the_builder PASSED [  4%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P01] PASSED [  5%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P02] PASSED [  6%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P03] PASSED [  7%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P04] PASSED [  7%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P05] PASSED [  8%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P06] PASSED [  9%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P07] PASSED [ 10%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P08] PASSED [ 11%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P09] PASSED [ 11%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P10] PASSED [ 12%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N01] PASSED [ 13%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N02] PASSED [ 14%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N03] PASSED [ 14%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N04] PASSED [ 15%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N05] PASSED [ 16%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N06] PASSED [ 17%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N07] PASSED [ 18%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N08] PASSED [ 18%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N09] PASSED [ 19%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N10] PASSED [ 20%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-G01] PASSED [ 21%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-G02] PASSED [ 22%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-G03] PASSED [ 22%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-G04] PASSED [ 23%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-G05] PASSED [ 24%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P01] PASSED [ 25%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P02] PASSED [ 25%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P03] PASSED [ 26%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P04] PASSED [ 27%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P05] PASSED [ 28%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P06] PASSED [ 29%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P07] PASSED [ 29%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P08] PASSED [ 30%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P09] PASSED [ 31%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N01] PASSED [ 32%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N02] PASSED [ 33%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N03] PASSED [ 33%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N04] PASSED [ 34%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N05] PASSED [ 35%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N06] PASSED [ 36%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N07] PASSED [ 37%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N08] PASSED [ 37%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N09] PASSED [ 38%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N10] PASSED [ 39%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-K01] PASSED [ 40%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-G01] PASSED [ 40%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-G02] PASSED [ 41%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-G03] PASSED [ 42%]
tests/test_sigma_rules.py::test_required_categories_and_tp_and_benign_present[re_lumma_001] PASSED [ 43%]
tests/test_sigma_rules.py::test_required_categories_and_tp_and_benign_present[re_lumma_002] PASSED [ 44%]
tests/test_sigma_rules.py::test_rule_against_case[R1-P01] PASSED         [ 44%]
tests/test_sigma_rules.py::test_rule_against_case[R1-P02] PASSED         [ 45%]
tests/test_sigma_rules.py::test_rule_against_case[R1-P03] PASSED         [ 46%]
tests/test_sigma_rules.py::test_rule_against_case[R1-P04] PASSED         [ 47%]
tests/test_sigma_rules.py::test_rule_against_case[R1-P05] PASSED         [ 48%]
tests/test_sigma_rules.py::test_rule_against_case[R1-P06] PASSED         [ 48%]
tests/test_sigma_rules.py::test_rule_against_case[R1-P07] PASSED         [ 49%]
tests/test_sigma_rules.py::test_rule_against_case[R1-P08] PASSED         [ 50%]
tests/test_sigma_rules.py::test_rule_against_case[R1-P09] PASSED         [ 51%]
tests/test_sigma_rules.py::test_rule_against_case[R1-P10] PASSED         [ 51%]
tests/test_sigma_rules.py::test_rule_against_case[R1-N01] PASSED         [ 52%]
tests/test_sigma_rules.py::test_rule_against_case[R1-N02] PASSED         [ 53%]
tests/test_sigma_rules.py::test_rule_against_case[R1-N03] PASSED         [ 54%]
tests/test_sigma_rules.py::test_rule_against_case[R1-N04] PASSED         [ 55%]
tests/test_sigma_rules.py::test_rule_against_case[R1-N05] PASSED         [ 55%]
tests/test_sigma_rules.py::test_rule_against_case[R1-N06] PASSED         [ 56%]
tests/test_sigma_rules.py::test_rule_against_case[R1-N07] PASSED         [ 57%]
tests/test_sigma_rules.py::test_rule_against_case[R1-N08] PASSED         [ 58%]
tests/test_sigma_rules.py::test_rule_against_case[R1-N09] PASSED         [ 59%]
tests/test_sigma_rules.py::test_rule_against_case[R1-N10] PASSED         [ 59%]
tests/test_sigma_rules.py::test_rule_against_case[R1-G01] PASSED         [ 60%]
tests/test_sigma_rules.py::test_rule_against_case[R1-G02] PASSED         [ 61%]
tests/test_sigma_rules.py::test_rule_against_case[R1-G03] PASSED         [ 62%]
tests/test_sigma_rules.py::test_rule_against_case[R1-G04] PASSED         [ 62%]
tests/test_sigma_rules.py::test_rule_against_case[R1-G05] PASSED         [ 63%]
tests/test_sigma_rules.py::test_rule_against_case[R2-P01] PASSED         [ 64%]
tests/test_sigma_rules.py::test_rule_against_case[R2-P02] PASSED         [ 65%]
tests/test_sigma_rules.py::test_rule_against_case[R2-P03] PASSED         [ 66%]
tests/test_sigma_rules.py::test_rule_against_case[R2-P04] PASSED         [ 66%]
tests/test_sigma_rules.py::test_rule_against_case[R2-P05] PASSED         [ 67%]
tests/test_sigma_rules.py::test_rule_against_case[R2-P06] PASSED         [ 68%]
tests/test_sigma_rules.py::test_rule_against_case[R2-P07] PASSED         [ 69%]
tests/test_sigma_rules.py::test_rule_against_case[R2-P08] PASSED         [ 70%]
tests/test_sigma_rules.py::test_rule_against_case[R2-P09] PASSED         [ 70%]
tests/test_sigma_rules.py::test_rule_against_case[R2-N01] PASSED         [ 71%]
tests/test_sigma_rules.py::test_rule_against_case[R2-N02] PASSED         [ 72%]
tests/test_sigma_rules.py::test_rule_against_case[R2-N03] PASSED         [ 73%]
tests/test_sigma_rules.py::test_rule_against_case[R2-N04] PASSED         [ 74%]
tests/test_sigma_rules.py::test_rule_against_case[R2-N05] PASSED         [ 74%]
tests/test_sigma_rules.py::test_rule_against_case[R2-N06] PASSED         [ 75%]
tests/test_sigma_rules.py::test_rule_against_case[R2-N07] PASSED         [ 76%]
tests/test_sigma_rules.py::test_rule_against_case[R2-N08] PASSED         [ 77%]
tests/test_sigma_rules.py::test_rule_against_case[R2-N09] PASSED         [ 77%]
tests/test_sigma_rules.py::test_rule_against_case[R2-N10] PASSED         [ 78%]
tests/test_sigma_rules.py::test_rule_against_case[R2-K01] PASSED         [ 79%]
tests/test_sigma_rules.py::test_rule_against_case[R2-G01] PASSED         [ 80%]
tests/test_sigma_rules.py::test_rule_against_case[R2-G02] PASSED         [ 81%]
tests/test_sigma_rules.py::test_rule_against_case[R2-G03] PASSED         [ 81%]
tests/test_sigma_rules.py::test_rule_does_not_fire_on_the_other_rules_events[re_lumma_001] PASSED [ 82%]
tests/test_sigma_rules.py::test_rule_does_not_fire_on_the_other_rules_events[re_lumma_002] PASSED [ 83%]
tests/test_sigma_rules.py::test_benign_corpus_counts_are_fixed PASSED    [ 84%]
tests/test_sigma_rules.py::test_benign_corpus_is_deterministic PASSED    [ 85%]
tests/test_sigma_rules.py::test_rule_001_silent_on_synthetic_benign_corpus PASSED [ 85%]
tests/test_sigma_rules.py::test_rule_002_silent_on_synthetic_benign_corpus PASSED [ 86%]
tests/test_config_extract.py::test_cipher_known_answer_zero_key PASSED   [ 87%]
tests/test_config_extract.py::test_round_trip_recovers_synthetic_config PASSED [ 88%]
tests/test_config_extract.py::test_blob_layout_matches_documented_offsets PASSED [ 88%]
tests/test_config_extract.py::test_ciphertext_does_not_contain_plaintext PASSED [ 89%]
tests/test_config_extract.py::test_blob_is_deterministic_and_seed_changes_it PASSED [ 90%]
tests/test_config_extract.py::test_parse_returns_the_parts PASSED        [ 91%]
tests/test_config_extract.py::test_short_blob_rejected[0] PASSED         [ 92%]
tests/test_config_extract.py::test_short_blob_rejected[1] PASSED         [ 92%]
tests/test_config_extract.py::test_short_blob_rejected[59] PASSED        [ 93%]
tests/test_config_extract.py::test_wrong_magic_rejected PASSED           [ 94%]
tests/test_config_extract.py::test_real_looking_file_is_refused PASSED   [ 95%]
tests/test_config_extract.py::test_truncated_ciphertext_rejected PASSED  [ 96%]
tests/test_config_extract.py::test_oversized_length_field_rejected PASSED [ 96%]
tests/test_config_extract.py::test_bad_key_or_nonce_length_rejected PASSED [ 97%]
tests/test_config_extract.py::test_wrong_key_does_not_recover_config PASSED [ 98%]
tests/test_config_extract.py::test_cli_refuses_non_synthetic_file PASSED [ 99%]
tests/test_config_extract.py::test_cli_decrypts_synthetic_blob PASSED    [100%]

============================= 127 passed in 0.39s =============================
```

### 9.2 Mutation suite (exit code 1)

M5 and M6 fail here because `yara` is not installed. They are failures, not passes.

```
============================= test session starts =============================
platform win32 -- Python 3.14.4, pytest-9.2.0, pluggy-1.7.0 -- C:\Users\Kevin\AppData\Local\Temp\claude\08b1cbd4ca292511\c6160613-be43-4100-835d-e20fda17383f\scratchpad\venv\Scripts\python.exe
rootdir: X:\Defensive-Engineering-Lab\re-lumma-stealer
configfile: pytest.ini
collecting ... collected 7 items

tests/test_mutations.py::test_baseline_unmutated_rules_have_no_red_cases PASSED [ 14%]
tests/test_mutations.py::test_m1_drop_encoded_variant_from_rule_001 PASSED [ 28%]
tests/test_mutations.py::test_m2_remove_parent_filter_from_rule_001 PASSED [ 42%]
tests/test_mutations.py::test_m3_remove_browser_filter_from_rule_002 PASSED [ 57%]
tests/test_mutations.py::test_m4_change_key_length_in_extractor PASSED   [ 71%]
tests/test_mutations.py::test_m5_remove_one_indicator_from_config_strings_rule FAILED [ 85%]
tests/test_mutations.py::test_m6_weaken_setup_condition_to_any_of FAILED [100%]

================================== FAILURES ===================================
E   ModuleNotFoundError: No module named 'yara'
X:\Defensive-Engineering-Lab\re-lumma-stealer\tests\test_mutations.py:98: ModuleNotFoundError: No module named 'yara'
E   ModuleNotFoundError: No module named 'yara'
X:\Defensive-Engineering-Lab\re-lumma-stealer\tests\test_mutations.py:98: ModuleNotFoundError: No module named 'yara'
=========================== short test summary info ===========================
FAILED tests/test_mutations.py::test_m5_remove_one_indicator_from_config_strings_rule
FAILED tests/test_mutations.py::test_m6_weaken_setup_condition_to_any_of - Mo...
========================= 2 failed, 5 passed in 0.13s =========================
```

### 9.3 YARA suite (exit code 2)

The file cannot be collected without `yara-python`. **No YARA test ran.**

```
============================= test session starts =============================
platform win32 -- Python 3.14.4, pytest-9.2.0, pluggy-1.7.0 -- C:\Users\Kevin\AppData\Local\Temp\claude\08b1cbd4ca292511\c6160613-be43-4100-835d-e20fda17383f\scratchpad\venv\Scripts\python.exe
rootdir: X:\Defensive-Engineering-Lab\re-lumma-stealer
configfile: pytest.ini
collecting ... collected 0 items / 1 error

=================================== ERRORS ====================================
__________________ ERROR collecting tests/test_yara_rules.py __________________
ImportError while importing test module 'X:\Defensive-Engineering-Lab\re-lumma-stealer\tests\test_yara_rules.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
C:\Python314\Lib\importlib\__init__.py:88: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests\test_yara_rules.py:17: in <module>
    import yara
E   ModuleNotFoundError: No module named 'yara'
=========================== short test summary info ===========================
ERROR tests/test_yara_rules.py
!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!!
============================== 1 error in 0.15s ===============================
```
