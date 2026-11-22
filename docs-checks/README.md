# docs-checks: tests for the documentation

This folder is not a detection module. It holds pytest checks that treat the repository's documentation as something to test, not trust. CI discovers it with the module folders (the discovery step in [`.github/workflows/detection-test.yml`](../.github/workflows/detection-test.yml) matches `docs-*/tests`) and runs it in the same matrix, so the same all-tests-passed gate covers it.

The checks are pure functions in [`tests/docs_lib.py`](./tests/docs_lib.py). Each takes an in-memory snapshot of the repository and returns a list of problems. [`tests/test_docs_checks.py`](./tests/test_docs_checks.py) runs them on the real repository.

## What is checked

| Check | Fails when |
|---|---|
| Links | A relative link or an anchor in any `.md` file does not resolve. The anchor must match a heading, using GitHub's slug rules. External URLs are not fetched. |
| Numbers | A README or `TESTING.md` quotes a count in prose that differs from the real one. "N tests" and "N passed" are compared with what `pytest --collect-only` finds for that suite. "N cases" and "N/N cases" are compared with the non-empty lines of the suite's `*.jsonl` corpus, or of the one corpus file the same line names. "N rules", "N Sigma rules" and "N YARA rules" are compared with the rule files. "N labelled raw log lines" and "N labelled cases" mean the same as "N cases". A phrase that can mean two things fails with a request for a clearer one: "N test cases" and "N case tests" (pytest tests or corpus cases?), "N labelled" followed by any other word (events, benign cases, nothing), and a line that names two corpus files. Fenced blocks are skipped here (see the next row). A number in root prose with no module context is rejected: link to the module's `TESTING.md` instead. |
| Pasted pytest output | In a fenced block of any `.md` file, a `collected N items` line (or `N tests collected`) or an `N passed` summary line differs from the real collected count of the suite the block names. A summary adds up passed, failed, skipped, deselected, xfailed, xpassed and errors; warnings are not counted. The suite comes from the block's `rootdir:` line or from the `<suite>/tests/` paths of its test ids. A block that names no suite, or two, fails and says so. Test id lines (`path::name`) are not read, because a parametrized id can hold any text. |
| Command tags | A command block in a README, `CONTRIBUTING.md` or `SECURITY.md` does not start with `# verified`, `# verified-locally: ...` or `# not verified: ...`. |
| Verified commands | A block tagged `# verified` exits non-zero when run from the repository root. A verified block may not call this suite, because it would run itself. |
| Module table | A row in the root README does not match a module folder, or a module folder is missing from the table, or lacks `README.md`, `TESTING.md`, `tests/requirements.txt` or a `tests/` directory. |
| Rule files | A Sigma rule lacks a UUID `id`, `level`, `status`, a non-empty `falsepositives`, or a header comment with a `SOURCE LIMITS` or `KNOWN COVERAGE GAPS` section. A YARA rule lacks `description`, `status` or `confidence` metadata, or a header comment. |
| Unique ids | A Sigma `id` or a YARA rule name is reused across rules anywhere in the repository. |
| Executable headers | Any file starts with a PE, ELF or Mach-O magic number. |
| File size | Any file is larger than 1 MiB. |
| Network indicators | A doc, a fixture, an issue template or `iocs.csv` holds an IP address outside the reserved ranges, or a domain that is not a reserved name or an allow-listed source. Defanged forms (`[.]`, `hxxp`) are normalised first, so a defanged real indicator is still caught. |
| Placeholders | The intake template's placeholder marker (an opening bracket followed by `ADD` and a colon) appears in a doc other than `SOC_INTAKE_RULEBOOK.md`. |
| Intake file | `SOC_INTAKE_RULEBOOK.md` is missing, or lacks a required field, or a field about an environment holds a value instead of a placeholder. Required placeholders: A3, B1 to B12, C1 to C6, E5, E6, F1 to F6 and G2 to G4. Allowed fixed answers: A1, A2, A4, A5, E1 to E4, G1 and H1 to H3. Any other field must be a placeholder. Placeholders may be wrapped in backticks. |

## Every check can fail

[`tests/test_docs_mutations.py`](./tests/test_docs_mutations.py) breaks one thing in an in-memory copy of the repository for each check, for example a broken link, a wrong count, a PE header in a fixture, a real IP address in a README, or a SIEM name typed into the rulebook. It then asserts that the check turns red with the expected message. Nothing on disk changes. A final test fails if any check has no mutation. This is the documentation counterpart of M1 to M7 in `re-lumma-stealer`.

For the count checks the mutations change a number (a stale corpus count, `collected` and `passed` lines), delete the suite marker of a pasted block (its `rootdir:` line and its test paths), make a block name two suites, and write a phrase that cannot be told apart ("N labelled benign events", "N case tests"). The other direction is tested too: `tests/test_docs_checks.py` feeds the checks small correct documents (a correct count in each accepted phrasing, a block with only a `rootdir:` line, a block with only test paths, a block with failures or deselected tests, one block per suite) and asserts they still pass.

## Run it

```bash
# verified-locally: 2026-11-22, in the python:3.12 container. Not tagged "verified" because the check refuses to run itself.
python -m pip install -r docs-checks/tests/requirements.txt
python -m pytest docs-checks/tests -q
```

Run it from the repository root, on Python 3.12. It installs the dependencies of every module, because it collects each module's tests to count them and runs the README commands that are tagged `# verified`. Those commands need `bash` on the path.

## Allow-lists

The network-indicator check allows:

- the RFC 5737 documentation ranges, RFC 1918 private ranges and loopback, which are not routable on the public internet;
- the two public resolver addresses `8.8.8.8` and `1.1.1.1`, which the `cwe-078` corpus uses as harmless ping targets;
- the reserved names `.example`, `.test`, `.invalid` and `.localhost`;
- a list of public source and documentation sites, each with its reason, in `ALLOWED_DOMAINS` in [`tests/docs_lib.py`](./tests/docs_lib.py).

Add a host to that list only because it is a cited source or a namespace URI, and say why next to it. Never add a host because it appeared in an indicator.

## What these checks do not do

- They do not judge whether a claim is true. They check that links resolve, counts match, commands run and the safety rules hold.
- External URLs are not fetched, so a dead external link passes.
- Domain detection uses a fixed list of top-level domains. A domain under a TLD that is not on the list is not caught.
- The prose number check only reads `README.md` and `TESTING.md` files, and only the phrases listed in the table. It does not check subset counts such as "N true positives" or "N benign", per-format or per-category counts, or the `N/N cases PASS` lines inside a pasted block.
- The pasted-output check compares only the `collected` and `passed` numbers with the current collection. It does not compare test ids, timings or versions, and it cannot tell whether the output was ever really produced: a block edited by hand to carry the right numbers passes.
- A `# verified` command is run only in the environment that runs this suite. That is Linux with bash in CI and in the container.
