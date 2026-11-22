# Testing: OS Command Injection Sigma Rule

![detection-test](https://github.com/ColdCoffeeSec/Defensive-Engineering-Lab/actions/workflows/detection-test.yml/badge.svg)


**Rule under test:** `detection_rules/cmdi_sigma.yml` (id `2bd67884-7866-4e1d-8b23-b383fa80e288`, level high)
**Corpus:** `tests/test_logs.jsonl`: 32 cases (16 true positives, 16 benign) in three log formats
**Runner:** `tests/test_rule.py` (pytest), executed on every push by `.github/workflows/detection-test.yml`

Each case is a **raw log line**. The suite parses it with a format-specific parser, checks the extracted fields against the case, then evaluates the rule's YAML and compares the verdict with the expected one. The corpus uses documentation IP ranges (RFC 5737) only.

## Coverage matrix

| Coverage requirement | Cases | What it proves |
|---|---|---|
| **True positive:** raw payloads (`;` `|` `$(` backtick) | `TP-01`, `TP-02`, `TP-03`, `TP-04` | Unencoded metacharacters, as sent by curl and simple scanners, are detected. |
| **True positive:** single URL-encoded | `TP-05`, `TP-06`, `TP-07`, `TP-08`, `TP-09` | `%3B` `%7c` `%26%26` `%0a` `%24%28` are detected, in upper- and lower-case hex. |
| **True positive:** double URL-encoded | `TP-10`, `TP-11` | `%253b` and `%257c` (filter-evasion attempts) are detected. |
| **True positive:** evasion (`${IFS}`) | `TP-12`, `TP-13` | `${IFS}` space substitution is detected, including as the *only* metacharacter (`TP-13`). |
| **True positive:** parameter scope | `TP-14`, `TP-15` | A parameter named `ping` is covered on any path and in any position. |
| **True positive:** scanner filter does not over-match | `TP-16` | The same payload as `B-06` from outside `192.0.2.0/24` still alerts. |
| **Benign:** legitimate pings | `B-01`, `B-02`, `B-03` | `ping=8.8.8.8`, a hostname with extra parameters, and a no-query health check do not alert. |
| **Benign:** raw unencoded `&&` | `B-04`, `B-05` | The server splits it into harmless separate parameters; it cannot inject and is not alerted on. |
| **Benign:** authorized scanner range `192.0.2.0/24` | `B-06` | A real payload from the allow-listed range is filtered. |
| **Benign:** unrelated endpoint | `B-07` | `/shipping` merely ends in the letters "ping"; no alert. |
| **Documented gap:** encoding and normalization | `B-09`, `B-10`, `B-11` | Triple-encoded `;` (`%25253b`) and the fullwidth semicolon U+FF1B (literal, and as `%EF%BC%9B`) are not detected. Each is a real attack only if something decodes or normalizes the value to `;` before it reaches a shell. |
| **Documented gap:** endpoint scope | `B-08`, `B-15` | A real payload on another path (`/diag`, `/ping.php`) with another parameter name is *not* detected. If your endpoint is on such a path, change the scope lines in the rule. |
| **Known false positive** | `B-16` | A hypothetical legitimate `;`-delimited multi-target ping (`a.example;b.example`) **alerts**. Pinned so the tuning advice stays visible: remove `;` from the payload lists if the feature is legitimate. The cost is shown below. |
| **Probe, not an evasion** | `B-12`, `B-13`, `B-14` | `%c0%af` (overlong UTF-8 `/`), tab (`%09`) and NUL (`%00`) are not shell command separators for this endpoint, so a miss is not a bypass. Kept as probes so the blind-spot analysis is on record. |

### Log format coverage

| Format | Cases | IDs |
|---|---|---|
| Nginx `combined` | 13 | `TP-01`, `TP-03`, `TP-06`, `TP-09`, `TP-12`, `TP-14`, `TP-16`, `B-01`, `B-04`, `B-06`, `B-09`, `B-12`, `B-15` |
| Apache `vhost_combined` | 11 | `TP-02`, `TP-04`, `TP-07`, `TP-10`, `TP-13`, `B-02`, `B-05`, `B-08`, `B-10`, `B-13`, `B-16` |
| IIS W3C extended | 8 | `TP-05`, `TP-08`, `TP-11`, `TP-15`, `B-03`, `B-07`, `B-11`, `B-14` |

## All 32 cases

| ID | Format | Source IP | Path | Query as logged | Expected | Why |
|---|---|---|---|---|---|---|
| `TP-01` | Nginx `combined` | `203.0.113.5` | `/ping` | `host=127.0.0.1;id` | **ALERT** | Raw ';' appends a second command after ping |
| `TP-02` | Apache `vhost_combined` | `203.0.113.7` | `/ping` | `ip=8.8.8.8\|cat%20/etc/passwd` | **ALERT** | Raw '\|' pipes ping output into another command |
| `TP-03` | Nginx `combined` | `198.51.100.23` | `/ping` | `ip=$(whoami)` | **ALERT** | Raw '$(' command substitution |
| `TP-04` | Apache `vhost_combined` | `198.51.100.23` | `/ping` | `ip=8.8.8.8`id`` | **ALERT** | Raw backtick command substitution |
| `TP-05` | IIS W3C extended | `203.0.113.9` | `/ping` | `host=127.0.0.1%3Bwhoami` | **ALERT** | Single-encoded ';' (%3B, upper-case hex) |
| `TP-06` | Nginx `combined` | `203.0.113.9` | `/ping` | `host=8.8.8.8%7ccat%20/etc/hosts` | **ALERT** | Single-encoded '\|' (%7c, lower-case hex) |
| `TP-07` | Apache `vhost_combined` | `203.0.113.77` | `/ping` | `ip=8.8.8.8%26%26id` | **ALERT** | Encoded '&&' (%26%26) stays inside the parameter value and is an effective separator |
| `TP-08` | IIS W3C extended | `203.0.113.77` | `/api/v1/ping` | `host=1.1.1.1%0aid` | **ALERT** | Encoded newline (%0a) starts a new command; also proves nested endpoint paths match |
| `TP-09` | Nginx `combined` | `198.51.100.41` | `/ping` | `ip=%24%28whoami%29` | **ALERT** | Encoded '$(' (%24%28) command substitution |
| `TP-10` | Apache `vhost_combined` | `198.51.100.41` | `/ping` | `ip=1.1.1.1%253bid` | **ALERT** | Double-encoded ';' (%253b), a filter-evasion attempt |
| `TP-11` | IIS W3C extended | `198.51.100.41` | `/ping` | `host=1.1.1.1%257cid` | **ALERT** | Double-encoded '\|' (%257c) |
| `TP-12` | Nginx `combined` | `203.0.113.120` | `/ping` | `host=8.8.8.8;cat${IFS}/etc/passwd` | **ALERT** | ${IFS} replaces the space to dodge space filters, combined with ';' |
| `TP-13` | Apache `vhost_combined` | `203.0.113.120` | `/ping` | `host=%24%7bIFS%7dwhoami` | **ALERT** | Encoded ${IFS} (%24%7b) as the ONLY metacharacter, proving the ${ pattern fires on its own |
| `TP-14` | Nginx `combined` | `203.0.113.150` | `/diag` | `ping=1.1.1.1;id` | **ALERT** | Parameter named 'ping' on a different path (scope B of the rule) |
| `TP-15` | IIS W3C extended | `203.0.113.150` | `/diag` | `count=4&ping=1.1.1.1%7Cid` | **ALERT** | 'ping' is not the first parameter; encoded pipe inside its value |
| `TP-16` | Nginx `combined` | `198.51.100.77` | `/ping` | `host=8.8.8.8;id` | **ALERT** | Same payload as B-06 from a source OUTSIDE 192.0.2.0/24: the scanner filter must not over-match |
| `B-01` | Nginx `combined` | `203.0.113.200` | `/ping` | `ping=8.8.8.8` | no alert | Legitimate use: parameter named ping carrying a plain IP |
| `B-02` | Apache `vhost_combined` | `203.0.113.201` | `/ping` | `host=example.com&count=4` | no alert | Legitimate multi-parameter request with a hostname |
| `B-03` | IIS W3C extended | `10.0.0.5` | `/ping` | `(none)` | no alert | Monitoring health check to /ping with no query string (IIS logs an empty query as '-') |
| `B-04` | Nginx `combined` | `203.0.113.210` | `/ping` | `host=8.8.8.8&&count=4` | no alert | Raw unencoded '&&' on /ping: the server splits it into harmless separate parameters |
| `B-05` | Apache `vhost_combined` | `203.0.113.210` | `/diag` | `ping=8.8.8.8&&id` | no alert | Raw unencoded '&&' after the ping parameter: 'id' becomes an empty separate parameter, no injection |
| `B-06` | Nginx `combined` | `192.0.2.10` | `/ping` | `host=8.8.8.8;id` | no alert | Real payload from the authorized scanner range 192.0.2.0/24 is filtered |
| `B-07` | IIS W3C extended | `203.0.113.230` | `/shipping` | `x=a;b` | no alert | '/shipping' ends in the letters 'ping' but is not the endpoint; no ping parameter |
| `B-08` | Apache `vhost_combined` | `203.0.113.240` | `/diag` | `host=1.1.1.1;id` | no alert | DOCUMENTED GAP: real payload, but neither path /ping nor a parameter named ping, so the rule does not fire (see TESTING.md) |
| `B-09` | Nginx `combined` | `198.51.100.90` | `/ping` | `host=1.1.1.1%25253bid` | no alert | DOCUMENTED GAP: triple-encoded ';'. The rule lists single and double encodings only. A real attack only if the value is decoded three times before a shell |
| `B-10` | Apache `vhost_combined` | `203.0.113.61` | `/ping` | `host=1.1.1.1；id` | no alert | DOCUMENTED GAP: fullwidth semicolon U+FF1B as the character itself. A real attack only if the application normalizes it to ';' (for example NFKC) before building the command |
| `B-11` | IIS W3C extended | `203.0.113.62` | `/ping` | `host=1.1.1.1%EF%BC%9Bid` | no alert | DOCUMENTED GAP: U+FF1B as percent-encoded UTF-8. A real attack only if it is decoded and then normalized to ';' |
| `B-12` | Nginx `combined` | `198.51.100.91` | `/ping` | `host=1.1.1.1%c0%afid` | no alert | PROBE, NOT AN EVASION: `%c0%af` is an overlong UTF-8 encoding of '/', not a command separator |
| `B-13` | Apache `vhost_combined` | `203.0.113.63` | `/ping` | `host=1.1.1.1%09id` | no alert | PROBE, NOT AN EVASION: a tab separates arguments in a shell, so 'id' would be an extra argument to ping, not a second command |
| `B-14` | IIS W3C extended | `203.0.113.64` | `/ping` | `host=1.1.1.1%00id` | no alert | PROBE, NOT AN EVASION: NUL is not a command separator; where strings end at NUL, the text after it is cut off |
| `B-15` | Nginx `combined` | `198.51.100.92` | `/ping.php` | `host=1.1.1.1;id` | no alert | DOCUMENTED GAP: endpoint scope is `/ping` only. If the vulnerable endpoint is `/ping.php` this IS a real attack and the scope lines must change |
| `B-16` | Apache `vhost_combined` | `203.0.113.65` | `/ping` | `host=a.example;b.example` | **ALERT** | KNOWN FALSE POSITIVE: a hypothetical legitimate `;`-delimited multi-target feature. The deployer removes `;` from the payload lists if it is legitimate; that also stops real `;` injections alerting |

## Run locally

```bash
python -m pip install -r tests/requirements.txt    # pytest, PyYAML
pytest tests/
```

`pytest tests/` prints PASS/FAIL per case (`-v` is set in `pytest.ini`) and ends with a matrix of all 32 cases. Run one case with `pytest tests/ -k TP-07`.

### Latest result

Run on 2026-11-22 in the `python:3.12` container (Python 3.12.16, pytest 9.2.0), from the repository root. The 32 case tests and 29 coverage, integrity and sensitivity checks all pass (excerpt):

```text
cwe-078-os-command-injection/tests/test_rule.py::test_case[TP-01] PASSED [ 16%]
cwe-078-os-command-injection/tests/test_rule.py::test_case[TP-02] PASSED [ 18%]
...
cwe-078-os-command-injection/tests/test_rule.py::test_case[B-16] PASSED  [ 67%]
...
32/32 cases PASS
============================== 61 passed in 0.35s ==============================
```

### Can these tests actually fail?

Yes. To check, the rule was deliberately broken in six ways on a throwaway copy; each change turned exactly the expected cases red.

| Deliberate break | Cases that failed |
|---|---|
| Drop `;` from the raw payload list | `TP-01`, `TP-16` |
| Re-add raw `&&` to the payload list | `B-04` |
| Remove the scanner filter from the condition | `B-06` |
| Loosen the endpoint match to `endswith 'ping'` | `B-07` |
| Point the scanner CIDR at the wrong range | `B-06` |
| Drop `%7c` from the encoded list | `TP-06` |

### Do the gap cases exercise what they claim?

Yes. `tests/test_gap_cases.py` adds the missing pattern to an **in-memory copy** of the rule and checks that exactly one case changes verdict. The rule file on disk is not changed, and the gap cases stay `no alert` in the corpus. This is a check on the cases, not a recommendation to close the gaps. For the probes that are not command separators (`B-12`, `B-13`, `B-14`) there is nothing to close.

| Pattern added to the copy | Only case that turns ALERT |
|---|---|
| `%25253b` in the double-encoded list | `B-09` |
| the character U+FF1B in the raw list | `B-10` |
| `%ef%bc%9b` in the encoded list | `B-11` |
| `%c0%af` in the encoded list | `B-12` |
| `%09` in the encoded list | `B-13` |
| `%00` in the encoded list | `B-14` |
| `/ping.php` in the endpoint list | `B-15` |

### What tuning away the known false positive costs

`B-16` alerts because `;` is in the raw payload list. `tests/test_gap_cases.py` removes `;` from that list in an in-memory copy of the rule: `B-16` stops alerting, but so do `TP-01` and `TP-16`, which are real `;` injections. Nothing else changes. So the tuning is a trade: only do it if the multi-target feature really exists, and cover the loss another way (for example a pattern for `;` followed by a command word, which this corpus does not test).

## Backend conversion (pySigma)

A CI job named `convert` (`.github/workflows/detection-test.yml`, part of the all-tests-passed gate) converts the rule with pySigma for two backends. `tools/convert_check.py` does the work. It **fails on any conversion error** and on a conversion that returns no query. The pinned versions are in `tests/requirements-conversion.txt`, a separate file because the packages do not all work together with the test dependencies (see below).

**What was converted.** Run on 2026-11-22 in the `python:3.12` container (Python 3.12.16) with pySigma 2.1.1:

| Target | Package | Result |
|---|---|---|
| `splunk` | `pySigma-backend-splunk` 3.0.1 (`SplunkBackend`) | `cmdi_sigma.yml` converted: 1 query, no error |
| `microsoft365defender` | `pySigma-backend-microsoft365defender` 0.3.2, which is a renamed stub of `pySigma-backend-kusto` 0.4.5 (`KustoBackend`) | `cmdi_sigma.yml` converted: 1 query, no error |

**The job fails when it should.** The same script, run in the container on deliberately broken input, exited 1 each time: a condition that names a selection that does not exist (`SigmaConditionError`), an unknown value modifier (`SigmaModifierError`), and a folder with no rule files. On the real rule it exited 0.

**What was NOT done, and what is not known.**

- **No pipeline and no field mapping was applied.** Neither backend ships one for the `webserver` log source. Checked in the installed packages: the Splunk pipelines cover the logsource categories `proxy` and `network`, and the Microsoft XDR pipelines cover `network_connection` and `process_creation`. The word `webserver` does not appear in either. It does appear in the `azuremonitor` and `sentinelasim` pipeline packages, which belong to other backends and were not used.
- **What a deployer must supply.** A mapping from the rule's field names to the field names, index or table that hold their web server logs. The detection uses `cs-uri-stem`, `cs-uri-query` and `c-ip`; the rule's `fields` list adds `cs-method`, `cs-host`, `sc-status` and `cs-user-agent`. Which Splunk fields or index, and whether Microsoft 365 Defender has any table for web server access logs, is the deployer's decision. **No mapping is invented here.**
- **The converted queries were not run** against Splunk or Microsoft 365 Defender, so they are not known to be valid there. The output passes the hyphenated field names through unmapped (for example `rex field=cs-uri-query "(?<cs-uri-queryMatch>...` for Splunk, and `''cs-uri-stem''` for Kusto). Those look unlikely to run as they are, which is another reason a field mapping is needed. That was not checked.
- **Why a separate requirements file.** `pySigma-backend-splunk` 3.0.1 requires `pysigma` 2.0.1 or newer and below 3. `pySigma-backend-kusto` 0.4.5 declares `pysigma >=0.10.0`, but its pipeline modules fail to import under pySigma 2.1.1 (`cannot import name 'SigmaTransformationError' from 'sigma.processing.transformations'`), so pySigma's plugin discovery crashes with it installed. The backend class itself imports and converts, and the script applies no pipeline, so the conversion works. Keep `requirements-conversion.txt` in its own environment, not next to `sigma-cli`.
- **The `convert` job itself has not run on GitHub.** Only the script was run, in the container. The workflow edit is unverified until a run is green.

To reproduce:

```bash
# verified-locally: 2026-11-22, in the python:3.12 container, in a fresh virtual environment
python -m pip install -r cwe-078-os-command-injection/tests/requirements-conversion.txt
python cwe-078-os-command-injection/tools/convert_check.py
```

## Scope and limits

- **Synthetic logs.** The corpus proves the rule logic and the three parsers, not detection rates or false-positive volume on live traffic. Measure the latter in your SIEM before raising the rule above `test` status.
- **Purpose-built evaluator.** `tests/test_rule.py` implements the Sigma subset this rule uses (`contains`, `startswith`, `endswith`, `re`, `cidr`, `all`, and `and`/`or`/`not`/`1 of`/`all of`). Unsupported syntax raises `NotImplementedError`, so rule edits cannot pass silently. It is not a SIEM backend: also convert the rule with `sigma-cli` for your platform and re-run these cases there. Regex dialects differ between backends. CI converts the rule for two backends without a pipeline, but nothing here runs the converted query (see Backend conversion).
- **Raw `&&` is a deliberate non-detection** (`B-04`, `B-05`). The server splits it into separate parameters, so it cannot inject. The effective encoded form `%26%26` is detected (`TP-07`).
- **Documented gaps (`B-08`, `B-09`, `B-10`, `B-11`, `B-15`).** The rule is scoped to paths ending in `/ping` or a parameter named `ping`, so a payload on another path (`/diag`, `/ping.php`) with another parameter name is not detected (`B-08`, `B-15`). Edit the scope lines in the rule if your endpoint differs, then change the expectation in `test_logs.jsonl` together with the rule. Triple-encoded `;` (`B-09`) and the fullwidth semicolon U+FF1B (`B-10`, `B-11`) are not detected either. Each would be a real attack only if something in the application decodes or normalizes the value to `;` first. No case in this corpus does that.
- **Known false positive (`B-16`).** The rule alerts on a `;`-delimited multi-target ping because `;` is a listed payload character. The corpus has no real endpoint with that feature; `B-16` is a hypothetical, pinned so the rule's `falsepositives` note is backed by a case.
- **Probes that are not evasions (`B-12`, `B-13`, `B-14`).** `%c0%af`, a tab (`%09`) and a NUL byte (`%00`) are not shell command separators for this endpoint, so the rule missing them is not a bypass. They are kept so the blind-spot analysis is on record. Their descriptions state how each behaves; that was reasoned about, not tested against a real endpoint.
- **POST bodies, cookies and headers are not in access logs**, so they cannot be tested here. See the rule header and `CTI_CONTEXT.md`.

## Adding a case

1. Append one JSON line to `tests/test_logs.jsonl` with the same keys as its neighbours: a real-format `raw` line, the `expected_fields` it should parse to, and `expected_detected`. IIS cases also carry `iis_fields` (the `#Fields:` header).
2. Add the `id` (in backticks) to the table above. A test fails if any case is missing from this file.
3. Update `EXPECTED_CASES` in `tests/test_rule.py`, and the case and test counts quoted in this file and in the README, then run `pytest tests/`. The `docs-checks` suite fails if a quoted count, or a `collected` or `passed` line in a pasted pytest block, drifts.
