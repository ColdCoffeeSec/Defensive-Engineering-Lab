[![Detection Tests](https://github.com/ColdCoffeeSec/Defensive-Engineering-Lab/actions/workflows/detection-test.yml/badge.svg)](https://github.com/ColdCoffeeSec/Defensive-Engineering-Lab/actions/workflows/detection-test.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

# Detection Engineering Portfolio

This repository holds detection-engineering modules. Each module pairs threat context with detection rules (Sigma, and YARA where a module has it), a test suite, and a Tier 1 incident response playbook. Tests run in CI. The `re-lumma-stealer` module also tags every claim in its docs as verified (V), unverified (U), analyst-derived (A) or assumed (ASSUMED); see its `CTI_CONTEXT.md`.

**Scope.** These are reference implementations with a verified test method. They are **not** detections proven in production. The tests check rule logic against synthetic data. They do not measure detection rates or false-positive rates, and no rule here has been validated on live traffic. Each module's `TESTING.md` lists what its tests do not show.

## Modules

| Module | Type | Rules included | Test status | Confidence | Limits |
|---|---|---|---|---|---|
| [`cwe-078-os-command-injection`](./cwe-078-os-command-injection/) | Weakness (CWE-78), web server logs | 1 Sigma rule | 60 passed, per its [latest result](./cwe-078-os-command-injection/TESTING.md#latest-result). Synthetic log corpus only. | Rule `status: test`, level high | [Scope and limits](./cwe-078-os-command-injection/TESTING.md#scope-and-limits): synthetic logs, a purpose-built evaluator that is not a SIEM backend, documented gaps and probes, POST bodies not visible in access logs, backend conversion checked in CI with no field mapping and never run on a SIEM |
| [`re-lumma-stealer`](./re-lumma-stealer/) | Reverse engineering (Lumma Stealer infostealer), endpoint, proxy and file telemetry | 3 Sigma rules, 2 YARA rules | 175 passed in the `python:3.12` container, per [TESTING.md](./re-lumma-stealer/TESTING.md). Baseline and real-data runs **not yet run**. | Rule 001 level medium; rule 002 level medium and **cannot fire** in the reference environment; rule 003 **low confidence**; both YARA rules **low confidence**; all `experimental` | [Known limits](./re-lumma-stealer/TESTING.md#8-known-limits): published-string YARA patterns never run on a real sample, no baseline, no SIEM backend conversion tested, several behaviours not covered |

Folder prefixes and the rule for adding a module are in [CONTRIBUTING.md](./CONTRIBUTING.md).

## How to use a module

1. **Read the module README and its limits first.** Start with the module's `README.md`, then the limits section of its `TESTING.md` (linked in the table above). Check which telemetry each rule needs before you plan anything.
2. **Fill in the intake rulebook privately.** Copy [`SOC_INTAKE_RULEBOOK.md`](./SOC_INTAKE_RULEBOOK.md) to a private location outside this repository, answer it there, and **never commit the filled copy**. The copy in this repository is a template. Its fields about an environment (telemetry, analysis capacity, tooling, response roles, redaction, legal limits and sign-off, plus A3) must keep their placeholders, while the answers that are fixed for this repository (module, identifier, end state, scope, repository, folder prefix, data classes and acceptance) are filled in. The `docs-checks` suite fails if an environment field holds a value.
3. **Compare your answers with the module's assumptions.** `re-lumma-stealer` has an [`ENVIRONMENT_ASSUMPTIONS.md`](./re-lumma-stealer/ENVIRONMENT_ASSUMPTIONS.md) that lists the reference environment its rules were written against. Every value in it is tagged `[ASSUMED]`. Compare it with your rulebook answers to see which rules apply to you, and see the module README for a per-rule table. `cwe-078-os-command-injection` has no such file. Its assumptions are in its [rule header](./cwe-078-os-command-injection/detection_rules/cmdi_sigma.yml) and the top of its [IR playbook](./cwe-078-os-command-injection/IR_PLAYBOOK.md).
4. **Convert, then deploy in alert-only mode first, then tune.** Convert each Sigma rule for your own backend and map the field names. Run it alert-only. Tune against your own traffic before you raise its status. The `cwe-078` module states the same limit: measure false positives in your SIEM before raising the rule above `test` status. Conversion steps are in the module README.

## Run the tests

From the repository root. Both routes use the dependencies in each module's `tests/requirements.txt`. The `re-lumma-stealer` ones are pinned to exact versions. The `cwe-078-os-command-injection` ones are minimum versions only (`pytest>=8.0`, `PyYAML>=6.0`).

Without Docker, on Python 3.12 (the version CI uses):

```bash
# verified
python -m pip install -r re-lumma-stealer/tests/requirements.txt -r cwe-078-os-command-injection/tests/requirements.txt
python -m pytest cwe-078-os-command-injection/tests -q
python -m pytest re-lumma-stealer/tests -q
```

With Docker, using the official image (PowerShell, from the repository root; the repository is mounted read-only):

```powershell
# verified-locally: 2026-11-22, Docker Desktop on Windows, image python:3.12
docker run --rm -e PYTHONDONTWRITEBYTECODE=1 -v "${PWD}:/repo:ro" -w /repo python:3.12 bash -c "pip install -q -r re-lumma-stealer/tests/requirements.txt && python -m pytest re-lumma-stealer/tests -p no:cacheprovider -q"
```

The same command for POSIX shells:

```bash
# not verified: written for POSIX shells but only the PowerShell form above was run
docker run --rm -e PYTHONDONTWRITEBYTECODE=1 -v "$PWD:/repo:ro" -w /repo python:3.12 bash -c "pip install -q -r re-lumma-stealer/tests/requirements.txt && python -m pytest re-lumma-stealer/tests -p no:cacheprovider -q"
```

`re-lumma-stealer/tests` needs Python 3.12 because `yara-python` has no Windows wheel for Python 3.14 (see [TESTING.md](./re-lumma-stealer/TESTING.md), section 1).

The documentation checks live in [`docs-checks`](./docs-checks/) and run in CI in the same matrix as the module tests. They check that links resolve, that quoted counts match what pytest collects, that commands tagged `# verified` run, and that the safety rules hold. To run them locally:

```bash
# verified-locally: 2026-11-22, in the python:3.12 container. Not tagged "verified" because the check refuses to run itself.
python -m pip install -r docs-checks/tests/requirements.txt
python -m pytest docs-checks/tests -q
```

## Repository layout

```text
.
├── .github/
│   ├── ISSUE_TEMPLATE/              # false-positive report, new-module request
│   └── workflows/detection-test.yml # CI: discovers modules, runs pytest on Python 3.12, converts the cwe-078 rule for two backends
├── cwe-078-os-command-injection/    # module
├── re-lumma-stealer/                # module
├── docs-checks/                     # tests that check the documentation, not a module
├── CONTRIBUTING.md
├── SECURITY.md
├── SOC_INTAKE_RULEBOOK.md           # blank template, never commit a filled copy
├── LICENSE
└── README.md
```

## Contributing, security, license

- [CONTRIBUTING.md](./CONTRIBUTING.md): how to add a module and run the suite.
- [SECURITY.md](./SECURITY.md): what counts as a security issue and how to report one privately.
- [LICENSE](./LICENSE): MIT.
