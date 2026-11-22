# Changelog

All notable changes to this repository are recorded here. Versions are 0.x while the modules are reference implementations: they have synthetic tests and documented limits, and no detection claims on real traffic.

## 0.1.0 (2026-11-22)

First tagged version.

### Modules

- **cwe-078-os-command-injection**: Sigma rule for OS command injection against a ping endpoint in web server logs, CTI brief, IR playbook, a labelled log corpus in three log formats, a pytest suite with documented gap and known false-positive cases, and a conversion check for the Splunk and Kusto backends.
- **re-lumma-stealer**: desk analysis of LummaC2 from public reports only (no sample was obtained or run), CTI context with source tags verified against raw pages, Sigma rules for ClickFix-style delivery (medium confidence), a non-browser read of browser credential stores (conditional: needs a Security 4663 SACL), and two known User-Agent strings (low confidence), two low-confidence YARA rules, a config extractor that only accepts synthetic blobs, an IR playbook, a hash-only indicator file, an ATT&CK v17 crosswalk, mutation tests, and a conversion check.
- **docs-checks**: tests for the documentation itself: links resolve, quoted counts and pasted pytest output match real runs, verified command blocks run, and safety lint for fixtures and docs. Each check has a mutation test that proves it can fail.

### Repository

- CI discovers modules automatically, runs each module's tests in a matrix, and gates on a single all-tests-passed job.
- Issue templates for false-positive reports and new-module requests, `CONTRIBUTING.md`, `SECURITY.md`, and an intake rulebook template that stays blank in the public repo.

### Known limits

- All fixtures are synthetic. The tests show rule logic, not detection rates or false-positive rates.
- Converted queries were never run on a SIEM, and no field mappings are provided for the web server log source.
- The Lumma YARA rules use published strings only and were never run on a real sample.
- The Lumma credential-store rule cannot fire without a Security 4663 SACL on browser profile paths.
- Playbooks are marked unreviewed.
