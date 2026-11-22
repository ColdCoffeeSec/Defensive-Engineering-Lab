# Contributing

Thanks for helping. This repository holds detection modules, and its rules are only as useful as the honesty of their documentation. These rules keep the claims checkable.

## Ground rules

- **No samples.** Never download, fetch, unpack, run or commit malware, a live payload or a real key. Commit hashes and defanged indicators only, each with its source and retrieval date. See [`re-lumma-stealer/ENVIRONMENT_ASSUMPTIONS.md`](./re-lumma-stealer/ENVIRONMENT_ASSUMPTIONS.md) for the fixture rules a module can assume.
- **Synthetic data only.** Fixtures use RFC 5737 addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and `.example` names. No real hostnames, IP addresses, user names, logs or customer data.
- **Never commit a filled intake rulebook.** [`SOC_INTAKE_RULEBOOK.md`](./SOC_INTAKE_RULEBOOK.md) is a template. Copy it outside the repository and fill it in there.
- **No invented values.** If you do not know a contact, policy, threshold or telemetry source, say it is not defined. Do not guess.
- **No metric targets before a baseline.** A detection-rate or false-positive target needs a recorded baseline and a reason. Until then say it is not set, as [`re-lumma-stealer/TESTING.md`](./re-lumma-stealer/TESTING.md) does.

## Tags

Every claim in a module's documentation says how well it is supported. The legend is in [`re-lumma-stealer/CTI_CONTEXT.md`](./re-lumma-stealer/CTI_CONTEXT.md#tag-legend):

| Tag | Meaning |
|---|---|
| **V** | Verified. The claim was found in a named source or shown by a run. |
| **U** | Unverified. Not used as a basis for a rule. |
| **A** | Analyst-derived. Your inference, to be confirmed before production use. |
| **ASSUMED** | A value from the module's environment-assumptions file. It is not a fact about any real environment. |

## The source-checking rule

A claim is tagged V only if its exact wording (a quote, a number, an ID or a date) is found by exact string search in the text of a page you downloaded, and the source is named. Otherwise tag it U.

- Do not rely on a summary of a page, including a summary written by a tool or another model. Search the raw text yourself.
- Keep downloaded pages outside the repository. They are untrusted data.
- Where a value is a paraphrase, do not put it in quotation marks.
- A hash taken from a source is matched exactly, in the case the source prints it. If you cannot match it, remove it or mark it unverified.

[`re-lumma-stealer/CTI_CONTEXT.md`](./re-lumma-stealer/CTI_CONTEXT.md#tag-legend) describes how this was done for that module.

## Adding a module

1. **Pick the folder prefix.** The prefixes in the intake rulebook (field E2) are `cwe-`, `ttp-`, `re-`, `cloud-` and `net-`. Use the CWE number or a short slug after it, for example `cwe-078-os-command-injection` or `re-lumma-stealer`. CI discovers only the `cwe-*`, `re-*` and `docs-*` folders today (see the discovery step in [`.github/workflows/detection-test.yml`](./.github/workflows/detection-test.yml)). A module under any other prefix is not tested in CI until the maintainers change that pattern.
2. **Required files**, checked by [`docs-checks`](./docs-checks/):
   - `README.md` and `TESTING.md` in the module folder.
   - A `tests/` directory with a `requirements.txt` and the pytest suite.
   - Each Sigma rule has an `id` (a UUID, unique across all modules), `status`, `level`, a `falsepositives` list, and a header comment that states its limits (a `SOURCE LIMITS` or `KNOWN COVERAGE GAPS` section).
   - Each YARA rule has `description`, `status` and `confidence` metadata and a header comment.
3. **Recommended files**, which both existing modules have: `CTI_CONTEXT.md`, `IR_PLAYBOOK.md`, `pytest.ini`, and an environment-assumptions file if the rules depend on telemetry.
4. **Tests.** Label every fixture with the verdict you expect. Include true positives, benign near-misses, and at least one documented gap that the rule does not catch. Add a mutation test for each rule, which breaks the rule in memory and shows the named cases turn red. See `tests/test_mutations.py` in [`re-lumma-stealer`](./re-lumma-stealer/tests/test_mutations.py) for an example.
5. **Say what the tests do not show.** Put it in the module's `TESTING.md`: synthetic data proves rule logic, not detection rates or false-positive rates.
6. **Add the module to the table** in the root [README](./README.md#modules).

## Running the suite

From the repository root, on Python 3.12 (the version CI uses). Run each module's suite separately, as CI does:

```bash
# verified
python -m pip install -r re-lumma-stealer/tests/requirements.txt -r cwe-078-os-command-injection/tests/requirements.txt
python -m pytest cwe-078-os-command-injection/tests -q
python -m pytest re-lumma-stealer/tests -q
```

The Docker route and the documentation checks are described in the root [README](./README.md#run-the-tests). Rule changes need their fixture first: add the case that shows the problem, then change the rule.

## Reporting problems

- A rule alerted on benign activity: use the **False-positive report** issue template. Redact real data first.
- A new module: use the **New module request** template.
- A committed secret, a real sample, or unsafe tool behaviour: do **not** open a public issue. See [SECURITY.md](./SECURITY.md).
