# Testing: OS Command Injection Sigma Rule

![detection-test](https://github.com/OWNER/REPO/actions/workflows/detection-test.yml/badge.svg)

> Replace `OWNER/REPO` in the badge URL with your repository path.

**Rule under test:** `detection_rules/cmdi_sigma.yml` (id `2bd67884-7866-4e1d-8b23-b383fa80e288`, level high)
**Corpus:** `tests/test_logs.jsonl`: 24 cases (16 true positives, 8 benign) in three real log formats
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
| **Documented gap** | `B-08` | A real payload on another path with another parameter name is *not* detected. Pinned so the gap stays visible. |

### Log format coverage

| Format | Cases | IDs |
|---|---|---|
| Nginx `combined` | 10 | `TP-01`, `TP-03`, `TP-06`, `TP-09`, `TP-12`, `TP-14`, `TP-16`, `B-01`, `B-04`, `B-06` |
| Apache `vhost_combined` | 8 | `TP-02`, `TP-04`, `TP-07`, `TP-10`, `TP-13`, `B-02`, `B-05`, `B-08` |
| IIS W3C extended | 6 | `TP-05`, `TP-08`, `TP-11`, `TP-15`, `B-03`, `B-07` |

## All 24 cases

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

## Run locally

```bash
python -m pip install -r tests/requirements.txt    # pytest, PyYAML
pytest tests/
```

`pytest tests/` prints PASS/FAIL per case (`-v` is set in `pytest.ini`) and ends with a matrix of all 24 cases. Run one case with `pytest tests/ -k TP-07`.

### Latest result

Run on 2026-11-22 (Python 3.13, pytest 9.1.1). The 24 case tests and 16 coverage and integrity checks all pass (excerpt):

```text
tests/test_rule.py::test_case[TP-01] PASSED
tests/test_rule.py::test_case[TP-02] PASSED
...
tests/test_rule.py::test_case[B-08] PASSED
...
24/24 cases PASS
============================== 40 passed in 0.07s ==============================
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

## Scope and limits

- **Synthetic logs.** The corpus proves the rule logic and the three parsers, not detection rates or false-positive volume on live traffic. Measure the latter in your SIEM before raising the rule above `test` status.
- **Purpose-built evaluator.** `tests/test_rule.py` implements the Sigma subset this rule uses (`contains`, `startswith`, `endswith`, `re`, `cidr`, `all`, and `and`/`or`/`not`/`1 of`/`all of`). Unsupported syntax raises `NotImplementedError`, so rule edits cannot pass silently. It is not a SIEM backend: also convert the rule with `sigma-cli` for your platform and re-run these cases there. Regex dialects differ between backends.
- **Raw `&&` is a deliberate non-detection** (`B-04`, `B-05`). The server splits it into separate parameters, so it cannot inject. The effective encoded form `%26%26` is detected (`TP-07`).
- **Documented gap (`B-08`).** The rule is scoped to the `/ping` path or a parameter named `ping`. A payload on another path with another parameter name is not detected. Edit the scope lines in the rule if your endpoint differs, then change the expectation in `test_logs.jsonl` together with the rule.
- **POST bodies, cookies and headers are not in access logs**, so they cannot be tested here. See the rule header and `CTI_CONTEXT.md`.

## Adding a case

1. Append one JSON line to `tests/test_logs.jsonl` with the same keys as its neighbours: a real-format `raw` line, the `expected_fields` it should parse to, and `expected_detected`. IIS cases also carry `iis_fields` (the `#Fields:` header).
2. Add the `id` (in backticks) to the table above. A test fails if any case is missing from this file.
3. Update the case count in `test_corpus_has_24_unique_cases`, then run `pytest tests/`.
