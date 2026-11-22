# Testing: re-lumma-stealer

**Last updated:** 2026-11-22. **Status:** the three Sigma rules, two YARA rules, config extractor and mutation tests (M1 to M7) were all run in the official `python:3.12` container on Python 3.12, the version CI uses. Result: 175 passed in 1.32s. **The baseline and real-data measurements have not been run (section 6), no metric targets are set, and the CI step has not been started.**

Tags follow `CTI_CONTEXT.md`: **[V]** verified by a run shown below, **[A]** analyst-derived, **[U]** unverified, **[ASSUMED]** from `ENVIRONMENT_ASSUMPTIONS.md`.

## 0. Roadmap status

| Step | Pass condition | Status |
|---|---|---|
| 2. CTI_CONTEXT.md, ANALYSIS.md | Every claim tagged V or U. Hash only for samples. | Written. Claims re-checked on 2026-11-22 against raw downloaded pages. No pytest applies. |
| 3. Sigma rules | Each rule has `falsepositives` and a source-limits note. | Done. Rules 001, 002 and 003 pass their cases (section 9). **Rule 003 is written, low confidence.** It replaces the earlier "not written" decision. Decision made 2026-11-22 by the repo owner (section 4.2). |
| 4. YARA rules | Rules compile and match their fixtures. | Done for what was claimed: both rules compile with **no warnings** under `error_on_warning=True` and match their synthetic fixtures. The patterns are published strings, low confidence **[A]**, never run on a real sample. |
| 5. IR_PLAYBOOK.md, iocs.csv | All indicators defanged. | Done. Playbook is **unreviewed**. 9 hashes matched exactly against the CISA page. |
| 6. Fixtures and pytest suite | Suite runs, ChaCha20 round trip passes. | Done. Full suite passes in the container (section 9). |
| 7. Mutation run | Every break turns its named cases red. | Done. M1 to M7 each turn exactly the expected cases red (section 5). |
| 8. TESTING.md with baseline | Baseline recorded. | This file. **Baseline not run** (section 6). |
| 9. CI change | Not started. | Not done. Waiting for confirmation. |

## 1. Environment of the runs below

| Item | Value |
|---|---|
| Image tag | `python:3.12` |
| Image digest | `python@sha256:5411fa1b302c43f510324381162b5f5d0d93b9ee2af538f09d944f0d290ee3cb` |
| Image created | 2026-11-05T09:40:41.434673518Z |
| Python in image | 3.12.16 (see output in section 9) |
| Container runtime | Docker Desktop, client 29.9.3, server 29.9.3, Linux engine, `linux/amd64` |
| Repo mount | `re-lumma-stealer/` mounted **read-only** at `/work`; `PYTHONDONTWRITEBYTECODE=1`, so the run cannot change the repo |
| Dependencies | installed in the container with `pip install -r tests/requirements.txt`; versions are printed in section 9 and match the pins |
| Network | the container had network access for `pip install` only; tests make no network calls |

An earlier run on Windows with Python 3.14 covered only the Sigma, extractor and M1 to M4 tests, because `yara-python` has no wheel for 3.14. It is superseded by the container run and its output is not reproduced here. Python 3.14 is not a supported target for the YARA tests.

## 2. What the tests do and do not show

- Sigma rules are evaluated by `tests/sigma_eval.py`, a small Sigma subset that raises on any syntax it does not know. Each rule is also parsed by pySigma. **No pySigma backend conversion was tested**, because no SIEM or backend is assumed (`ENVIRONMENT_ASSUMPTIONS.md` section 1).
- Cases are synthetic Windows event XML in the shape Windows writes for Sysmon 1 and Security 4663. YARA fixtures are synthetic filler bytes with the rules' own strings dropped in. No real log or sample is used.
- A pass shows the rule logic matches the labelled cases. **It is not a detection rate or a false-positive rate.**
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

CI-equivalent, in the same image (from the repo root; the mount is read-only):

```
docker run --rm -e PYTHONDONTWRITEBYTECODE=1 -v "<path-to>/re-lumma-stealer:/work:ro" -w /work python:3.12 \
  bash -c "pip install -q -r tests/requirements.txt && python -m pytest tests -p no:cacheprovider -v"
```

Or without Docker, on Python 3.12:

```
python -m pip install -r tests/requirements.txt
python tests/fixtures/build_cases.py     # regenerates the JSONL (a test checks it is current)
python -m pytest tests -v
```

Pin the image by digest (`python@sha256:5411fa1b302c43f510324381162b5f5d0d93b9ee2af538f09d944f0d290ee3cb`) if you need the same bytes again; the `python:3.12` tag moves.

## 8. Known limits

- Rule 003 is written at **low confidence** (section 4.2; decision made 2026-11-22 by the repo owner). Microsoft published no C2 User-Agent **[V: absent]**; the rule uses only the two strings ESET lists **[V: ESET]**. Legitimate traffic can use those Chrome versions, proxy logs do not record the process name so the rule cannot confirm the source process, and there is no local baseline of normal traffic. It is blind when HTTPS is not inspected.
- Rule 001 misses: PowerShell started through `cmd.exe`, renamed copies, string-assembled cradles, and truncated command lines (cases R1-G01 to R1-G05).
- Rule 002 misses: injection into a browser process, path-suffix spoofing, and browsers whose profile is not under `User Data` such as Opera (cases R2-G01 to R2-G03).
- Process hollowing, in-memory loading and C2 content need telemetry the reference environment does not assume.
- YARA rules use published strings only. Elastic reports parts of the ChaCha20 constant are decrypted at runtime and XOR-ROL derived **[V]**, so the setup rule may miss the family it names, and it will match benign programs that use ChaCha20 and WinHTTP.
- The `pe` module is not used, so no condition is untestable on synthetic filler.
- ATT&CK IDs are confirmed as listed on the MITRE S1213 page (footer v20.1) and, for some, in AA25-141B (v17), but are not checked against the v17 matrix (`CTI_CONTEXT.md` section 3).
- Source claims in the docs were re-verified on 2026-11-22 against raw downloaded pages by exact string match. `iocs.csv` hashes were matched exactly, case included.

## 9. Real test output

All output below was produced on 2026-11-22 by the script that wrote this file, in the `python:3.12` container. Nothing is edited.

### 9.1 Full suite, exit code 0

```
Python 3.12.16

--- installed:
cryptography        50.0.2
pySigma             2.1.1
pytest              9.2.0
PyYAML              6.0.4
yara-python         4.5.4
yara.YARA_VERSION = 4.5.4
--- pytest (full suite):
============================= test session starts ==============================
platform linux -- Python 3.12.16, pytest-9.2.0, pluggy-1.7.0 -- /usr/local/bin/python
rootdir: /work
configfile: pytest.ini
collecting ... collected 175 items

tests/test_config_extract.py::test_cipher_known_answer_zero_key PASSED   [  0%]
tests/test_config_extract.py::test_round_trip_recovers_synthetic_config PASSED [  1%]
tests/test_config_extract.py::test_blob_layout_matches_documented_offsets PASSED [  1%]
tests/test_config_extract.py::test_ciphertext_does_not_contain_plaintext PASSED [  2%]
tests/test_config_extract.py::test_blob_is_deterministic_and_seed_changes_it PASSED [  2%]
tests/test_config_extract.py::test_parse_returns_the_parts PASSED        [  3%]
tests/test_config_extract.py::test_short_blob_rejected[0] PASSED         [  4%]
tests/test_config_extract.py::test_short_blob_rejected[1] PASSED         [  4%]
tests/test_config_extract.py::test_short_blob_rejected[59] PASSED        [  5%]
tests/test_config_extract.py::test_wrong_magic_rejected PASSED           [  5%]
tests/test_config_extract.py::test_real_looking_file_is_refused PASSED   [  6%]
tests/test_config_extract.py::test_truncated_ciphertext_rejected PASSED  [  6%]
tests/test_config_extract.py::test_oversized_length_field_rejected PASSED [  7%]
tests/test_config_extract.py::test_bad_key_or_nonce_length_rejected PASSED [  8%]
tests/test_config_extract.py::test_wrong_key_does_not_recover_config PASSED [  8%]
tests/test_config_extract.py::test_cli_refuses_non_synthetic_file PASSED [  9%]
tests/test_config_extract.py::test_cli_decrypts_synthetic_blob PASSED    [  9%]
tests/test_mutations.py::test_baseline_unmutated_rules_have_no_red_cases PASSED [ 10%]
tests/test_mutations.py::test_m1_drop_encoded_variant_from_rule_001 PASSED [ 10%]
tests/test_mutations.py::test_m2_remove_parent_filter_from_rule_001 PASSED [ 11%]
tests/test_mutations.py::test_m3_remove_browser_filter_from_rule_002 PASSED [ 12%]
tests/test_mutations.py::test_m7_drop_the_chrome_109_user_agent_from_rule_003 PASSED [ 12%]
tests/test_mutations.py::test_m4_change_key_length_in_extractor PASSED   [ 13%]
tests/test_mutations.py::test_m5_remove_one_indicator_from_config_strings_rule PASSED [ 13%]
tests/test_mutations.py::test_m6_weaken_setup_condition_to_any_of PASSED [ 14%]
tests/test_sigma_rules.py::test_pysigma_version_matches_pin PASSED       [ 14%]
tests/test_sigma_rules.py::test_rule_parses_with_pysigma_and_has_required_metadata[re_lumma_001] PASSED [ 15%]
tests/test_sigma_rules.py::test_rule_parses_with_pysigma_and_has_required_metadata[re_lumma_002] PASSED [ 16%]
tests/test_sigma_rules.py::test_rule_parses_with_pysigma_and_has_required_metadata[re_lumma_003] PASSED [ 16%]
tests/test_sigma_rules.py::test_rule_ids_are_unique PASSED               [ 17%]
tests/test_sigma_rules.py::test_rule_002_declares_that_it_cannot_fire_in_the_reference_environment PASSED [ 17%]
tests/test_sigma_rules.py::test_rule_003_contains_exactly_the_two_eset_user_agents PASSED [ 18%]
tests/test_sigma_rules.py::test_rule_003_header_states_tags_confidence_and_the_three_limits PASSED [ 18%]
tests/test_sigma_rules.py::test_committed_case_files_match_the_builder PASSED [ 19%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P01] PASSED [ 20%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P02] PASSED [ 20%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P03] PASSED [ 21%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P04] PASSED [ 21%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P05] PASSED [ 22%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P06] PASSED [ 22%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P07] PASSED [ 23%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P08] PASSED [ 24%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P09] PASSED [ 24%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-P10] PASSED [ 25%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N01] PASSED [ 25%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N02] PASSED [ 26%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N03] PASSED [ 26%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N04] PASSED [ 27%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N05] PASSED [ 28%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N06] PASSED [ 28%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N07] PASSED [ 29%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N08] PASSED [ 29%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N09] PASSED [ 30%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-N10] PASSED [ 30%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-G01] PASSED [ 31%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-G02] PASSED [ 32%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-G03] PASSED [ 32%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-G04] PASSED [ 33%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R1-G05] PASSED [ 33%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P01] PASSED [ 34%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P02] PASSED [ 34%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P03] PASSED [ 35%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P04] PASSED [ 36%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P05] PASSED [ 36%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P06] PASSED [ 37%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P07] PASSED [ 37%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P08] PASSED [ 38%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-P09] PASSED [ 38%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N01] PASSED [ 39%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N02] PASSED [ 40%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N03] PASSED [ 40%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N04] PASSED [ 41%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N05] PASSED [ 41%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N06] PASSED [ 42%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N07] PASSED [ 42%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N08] PASSED [ 43%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N09] PASSED [ 44%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-N10] PASSED [ 44%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-K01] PASSED [ 45%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-G01] PASSED [ 45%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-G02] PASSED [ 46%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R2-G03] PASSED [ 46%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R3-P01] PASSED [ 47%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R3-P02] PASSED [ 48%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R3-N01] PASSED [ 48%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R3-N02] PASSED [ 49%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R3-K01] PASSED [ 49%]
tests/test_sigma_rules.py::test_case_schema_and_parsed_fields[R3-G01] PASSED [ 50%]
tests/test_sigma_rules.py::test_required_categories_and_tp_and_benign_present[re_lumma_001] PASSED [ 50%]
tests/test_sigma_rules.py::test_required_categories_and_tp_and_benign_present[re_lumma_002] PASSED [ 51%]
tests/test_sigma_rules.py::test_required_categories_and_tp_and_benign_present[re_lumma_003] PASSED [ 52%]
tests/test_sigma_rules.py::test_rule_against_case[R1-P01] PASSED         [ 52%]
tests/test_sigma_rules.py::test_rule_against_case[R1-P02] PASSED         [ 53%]
tests/test_sigma_rules.py::test_rule_against_case[R1-P03] PASSED         [ 53%]
tests/test_sigma_rules.py::test_rule_against_case[R1-P04] PASSED         [ 54%]
tests/test_sigma_rules.py::test_rule_against_case[R1-P05] PASSED         [ 54%]
tests/test_sigma_rules.py::test_rule_against_case[R1-P06] PASSED         [ 55%]
tests/test_sigma_rules.py::test_rule_against_case[R1-P07] PASSED         [ 56%]
tests/test_sigma_rules.py::test_rule_against_case[R1-P08] PASSED         [ 56%]
tests/test_sigma_rules.py::test_rule_against_case[R1-P09] PASSED         [ 57%]
tests/test_sigma_rules.py::test_rule_against_case[R1-P10] PASSED         [ 57%]
tests/test_sigma_rules.py::test_rule_against_case[R1-N01] PASSED         [ 58%]
tests/test_sigma_rules.py::test_rule_against_case[R1-N02] PASSED         [ 58%]
tests/test_sigma_rules.py::test_rule_against_case[R1-N03] PASSED         [ 59%]
tests/test_sigma_rules.py::test_rule_against_case[R1-N04] PASSED         [ 60%]
tests/test_sigma_rules.py::test_rule_against_case[R1-N05] PASSED         [ 60%]
tests/test_sigma_rules.py::test_rule_against_case[R1-N06] PASSED         [ 61%]
tests/test_sigma_rules.py::test_rule_against_case[R1-N07] PASSED         [ 61%]
tests/test_sigma_rules.py::test_rule_against_case[R1-N08] PASSED         [ 62%]
tests/test_sigma_rules.py::test_rule_against_case[R1-N09] PASSED         [ 62%]
tests/test_sigma_rules.py::test_rule_against_case[R1-N10] PASSED         [ 63%]
tests/test_sigma_rules.py::test_rule_against_case[R1-G01] PASSED         [ 64%]
tests/test_sigma_rules.py::test_rule_against_case[R1-G02] PASSED         [ 64%]
tests/test_sigma_rules.py::test_rule_against_case[R1-G03] PASSED         [ 65%]
tests/test_sigma_rules.py::test_rule_against_case[R1-G04] PASSED         [ 65%]
tests/test_sigma_rules.py::test_rule_against_case[R1-G05] PASSED         [ 66%]
tests/test_sigma_rules.py::test_rule_against_case[R2-P01] PASSED         [ 66%]
tests/test_sigma_rules.py::test_rule_against_case[R2-P02] PASSED         [ 67%]
tests/test_sigma_rules.py::test_rule_against_case[R2-P03] PASSED         [ 68%]
tests/test_sigma_rules.py::test_rule_against_case[R2-P04] PASSED         [ 68%]
tests/test_sigma_rules.py::test_rule_against_case[R2-P05] PASSED         [ 69%]
tests/test_sigma_rules.py::test_rule_against_case[R2-P06] PASSED         [ 69%]
tests/test_sigma_rules.py::test_rule_against_case[R2-P07] PASSED         [ 70%]
tests/test_sigma_rules.py::test_rule_against_case[R2-P08] PASSED         [ 70%]
tests/test_sigma_rules.py::test_rule_against_case[R2-P09] PASSED         [ 71%]
tests/test_sigma_rules.py::test_rule_against_case[R2-N01] PASSED         [ 72%]
tests/test_sigma_rules.py::test_rule_against_case[R2-N02] PASSED         [ 72%]
tests/test_sigma_rules.py::test_rule_against_case[R2-N03] PASSED         [ 73%]
tests/test_sigma_rules.py::test_rule_against_case[R2-N04] PASSED         [ 73%]
tests/test_sigma_rules.py::test_rule_against_case[R2-N05] PASSED         [ 74%]
tests/test_sigma_rules.py::test_rule_against_case[R2-N06] PASSED         [ 74%]
tests/test_sigma_rules.py::test_rule_against_case[R2-N07] PASSED         [ 75%]
tests/test_sigma_rules.py::test_rule_against_case[R2-N08] PASSED         [ 76%]
tests/test_sigma_rules.py::test_rule_against_case[R2-N09] PASSED         [ 76%]
tests/test_sigma_rules.py::test_rule_against_case[R2-N10] PASSED         [ 77%]
tests/test_sigma_rules.py::test_rule_against_case[R2-K01] PASSED         [ 77%]
tests/test_sigma_rules.py::test_rule_against_case[R2-G01] PASSED         [ 78%]
tests/test_sigma_rules.py::test_rule_against_case[R2-G02] PASSED         [ 78%]
tests/test_sigma_rules.py::test_rule_against_case[R2-G03] PASSED         [ 79%]
tests/test_sigma_rules.py::test_rule_against_case[R3-P01] PASSED         [ 80%]
tests/test_sigma_rules.py::test_rule_against_case[R3-P02] PASSED         [ 80%]
tests/test_sigma_rules.py::test_rule_against_case[R3-N01] PASSED         [ 81%]
tests/test_sigma_rules.py::test_rule_against_case[R3-N02] PASSED         [ 81%]
tests/test_sigma_rules.py::test_rule_against_case[R3-K01] PASSED         [ 82%]
tests/test_sigma_rules.py::test_rule_against_case[R3-G01] PASSED         [ 82%]
tests/test_sigma_rules.py::test_rule_does_not_fire_on_the_other_rules_events[re_lumma_001] PASSED [ 83%]
tests/test_sigma_rules.py::test_rule_does_not_fire_on_the_other_rules_events[re_lumma_002] PASSED [ 84%]
tests/test_sigma_rules.py::test_rule_does_not_fire_on_the_other_rules_events[re_lumma_003] PASSED [ 84%]
tests/test_sigma_rules.py::test_benign_corpus_counts_are_fixed PASSED    [ 85%]
tests/test_sigma_rules.py::test_benign_corpus_is_deterministic PASSED    [ 85%]
tests/test_sigma_rules.py::test_rule_001_silent_on_synthetic_benign_corpus PASSED [ 86%]
tests/test_sigma_rules.py::test_rule_002_silent_on_synthetic_benign_corpus PASSED [ 86%]
tests/test_sigma_rules.py::test_rule_003_silent_on_synthetic_benign_proxy_corpus PASSED [ 87%]
tests/test_yara_rules.py::test_yara_python_version_matches_pin PASSED    [ 88%]
tests/test_yara_rules.py::test_rule_file_compiles_without_warnings_and_declares_its_basis[re_lumma_config_strings.yar] PASSED [ 88%]
tests/test_yara_rules.py::test_rule_file_compiles_without_warnings_and_declares_its_basis[re_lumma_chacha_setup.yar] PASSED [ 89%]
tests/test_yara_rules.py::test_rules_do_not_use_pe_module[re_lumma_config_strings.yar] PASSED [ 89%]
tests/test_yara_rules.py::test_rules_do_not_use_pe_module[re_lumma_chacha_setup.yar] PASSED [ 90%]
tests/test_yara_rules.py::test_fixtures_are_non_executable PASSED        [ 90%]
tests/test_yara_rules.py::test_config_strings_rule_against_fixture[cfg_negative_filler] PASSED [ 91%]
tests/test_yara_rules.py::test_config_strings_rule_against_fixture[cfg_negative_no_param] PASSED [ 92%]
tests/test_yara_rules.py::test_config_strings_rule_against_fixture[cfg_negative_no_version] PASSED [ 92%]
tests/test_yara_rules.py::test_config_strings_rule_against_fixture[cfg_negative_two_commands] PASSED [ 93%]
tests/test_yara_rules.py::test_config_strings_rule_against_fixture[cfg_positive_all] PASSED [ 93%]
tests/test_yara_rules.py::test_config_strings_rule_against_fixture[cfg_positive_lid_variant] PASSED [ 94%]
tests/test_yara_rules.py::test_config_strings_rule_against_fixture[cfg_positive_uid_variant] PASSED [ 94%]
tests/test_yara_rules.py::test_setup_rule_against_fixture[setup_negative_constant_and_dll] PASSED [ 95%]
tests/test_yara_rules.py::test_setup_rule_against_fixture[setup_negative_constant_only] PASSED [ 96%]
tests/test_yara_rules.py::test_setup_rule_against_fixture[setup_negative_filler] PASSED [ 96%]
tests/test_yara_rules.py::test_setup_rule_against_fixture[setup_negative_winhttp_only] PASSED [ 97%]
tests/test_yara_rules.py::test_setup_rule_against_fixture[setup_positive_all] PASSED [ 97%]
tests/test_yara_rules.py::test_setup_rule_against_fixture[setup_positive_wide_dll] PASSED [ 98%]
tests/test_yara_rules.py::test_each_rule_ignores_the_other_rules_positives PASSED [ 98%]
tests/test_yara_rules.py::test_rules_ignore_the_synthetic_config_blob PASSED [ 99%]
tests/test_yara_rules.py::test_fixture_sets_are_deterministic PASSED     [100%]

============================= 175 passed in 1.32s ==============================
pytest exit code: 0
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
exit code: 0
```
