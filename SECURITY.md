# Security policy

## What counts as a security issue here

This repository contains detection rules, test fixtures and small tools. Report it as a security issue if you find:

- **A committed secret**: a key, token, password or credential, in any file or in history.
- **A real sample or payload**: malware, a live payload or an executable committed as a fixture. Fixtures must be synthetic and non-executable.
- **Real indicators or personal data**: real hostnames, IP addresses, user names, customer data or filled-in intake answers. The repository allows only reserved addresses, `.example` names and the hashes listed in `iocs.csv`.
- **Unsafe tool behaviour**: for example, `re-lumma-stealer/tools/config_extract.py` accepting a file that is not a synthetic test blob, reading without a size limit, or executing data it parses. The tests are meant to run only on blobs they generate in memory.
- **A CI or workflow weakness** in `.github/workflows/`, such as a step that runs untrusted input or grants more permission than it needs.
- **A way the test harness runs untrusted data** (a fixture that executes, or a test that downloads and runs something).

## How to report

Use GitHub private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**, or go to <https://github.com/ColdCoffeeSec/Defensive-Engineering-Lab/security/advisories/new>. Do not post exploit details, secrets or sample data in a public issue, a pull request or a discussion. No response-time commitment is made.

If the **Report a vulnerability** option is not offered, private vulnerability reporting is not enabled for the repository yet, and the maintainer needs to turn it on in the repository settings.

## What is not a security issue

- **A false positive or false negative in a rule.** Rules are **not a security guarantee**. They are reference implementations tested on synthetic data, and each module's `TESTING.md` lists what its tests do not show. Use the **False-positive report** issue template for rule problems.
- **A documented gap.** Known evasions are listed in each module's `TESTING.md`.
- **A request for a new module.** Use the **New module request** issue template.
