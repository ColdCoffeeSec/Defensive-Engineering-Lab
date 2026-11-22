"""Prove every documentation check can fail.

Each entry breaks ONE thing in an in-memory copy of the repository snapshot and names the message the check must
produce. Nothing on disk changes. This is the docs counterpart of M1 to M7 in re-lumma-stealer/tests/test_mutations.py.
A check that never turns red on a mutation would pass no matter what the docs said, so
test_every_check_has_a_mutation fails if a check has none.
"""
import re

import pytest

import docs_lib as d

README = "README.md"
MOD_README = "re-lumma-stealer/README.md"
CWE_README = "cwe-078-os-command-injection/README.md"
CWE_TESTING = "cwe-078-os-command-injection/TESTING.md"
LUMMA_TESTING = "re-lumma-stealer/TESTING.md"
CONTRIB = "CONTRIBUTING.md"
RULE001 = "re-lumma-stealer/detection_rules/sigma/re_lumma_001_clickfix_user_powershell.yml"
YARA_CFG = "re-lumma-stealer/detection_rules/yara/re_lumma_config_strings.yar"


# --------------------------------------------------------------------------- how each check is run
def _runners(truth, root):
    return {
        "links": lambda r: d.check_links(r),
        "numbers": lambda r: d.check_numbers(r, truth),
        "pasted-output": lambda r: d.check_pasted_pytest_output(r, truth),
        "command-tags": lambda r: d.check_command_tags(r),
        "command-run": lambda r: d.check_verified_commands(r, lambda s: d.run_bash(s, root)),
        "module-table": lambda r: d.check_module_table(r),
        "sigma-rules": lambda r: d.check_sigma_rules(r),
        "yara-rules": lambda r: d.check_yara_rules(r),
        "rule-ids-unique": lambda r: d.check_rule_ids_unique(r),
        "exec-headers": lambda r: d.check_no_executable_headers(r),
        "file-size": lambda r: d.check_file_sizes(r),
        "network-indicators": lambda r: d.check_network_indicators(r),
        "placeholders": lambda r: d.check_no_placeholders_in_docs(r),
        "intake": lambda r: d.check_intake_file(r),
    }


# --------------------------------------------------------------------------- small mutation helpers
def edit(path, old, new, count=1):
    def go(repo):
        text = repo.text(path)
        assert text.count(old) >= 1, f"mutation anchor not found in {path}: {old!r}"
        if count is not None:
            assert text.count(old) == count, f"{old!r} occurs {text.count(old)} times in {path}"
        repo.set_text(path, text.replace(old, new))
        return repo
    return go


def append(path, extra):
    def go(repo):
        repo.set_text(path, repo.text(path) + extra)
        return repo
    return go


def add_file(path, data):
    def go(repo):
        repo.files[path] = data
        return repo
    return go


def drop_lines(path, containing):
    def go(repo):
        lines = repo.text(path).split("\n")
        kept = [l for l in lines if containing not in l]
        assert len(kept) < len(lines), f"no line containing {containing!r} in {path}"
        repo.set_text(path, "\n".join(kept))
        return repo
    return go


def drop_file(path):
    def go(repo):
        del repo.files[path]
        return repo
    return go


def drop_dir(prefix):
    def go(repo):
        gone = [p for p in repo.files if p.startswith(prefix)]
        assert gone, f"nothing under {prefix}"
        for p in gone:
            del repo.files[p]
        return repo
    return go


def strip_suite_markers(path, suite):
    """Delete what tells a pasted pytest block which suite it is from: every `rootdir:` line and `<suite>/tests/` path."""
    def go(repo):
        text = repo.text(path)
        new = re.sub(r"(?m)^rootdir:.*\n", "", text).replace(f"{suite}/tests/", "tests/")
        assert new != text, f"no suite marker for {suite} in {path}"
        repo.set_text(path, new)
        return repo
    return go


def only_readme_with_failing_command(repo):
    """A one-file snapshot whose `# verified` block is replaced by a command that fails."""
    text = repo.text(README)
    body = re.sub(r"(```bash\n# verified\n).*?(\n```)", r"\1exit 3\2", text, count=1, flags=re.S)
    assert body != text
    return d.Repo({README: body.encode("utf-8")})


def verified_block_calls_docs_checks(repo):
    text = repo.text(README)
    body = text.replace("# verified\npython -m pip install", "# verified\npython -m pytest docs-checks/tests -q\npython -m pip install", 1)
    assert body != text
    return d.Repo({README: body.encode("utf-8")})


def intake_fill(field, value):
    def go(repo):
        text = repo.text(d.INTAKE_FILE)
        new, n = re.subn(rf"^(\*\*{field}\. .*?\*\*\s*→\s*).*$", rf"\g<1>{value}", text, count=1, flags=re.M)
        assert n == 1
        repo.set_text(d.INTAKE_FILE, new)
        return repo
    return go


# check name, label, mutation, text that must appear in at least one problem
MUTATIONS = [
    ("links", "link to a file that does not exist", edit(README, "(./CONTRIBUTING.md)", "(./CONTRIBUTING-MISSING.md)", None), "broken link"),
    ("links", "anchor that matches no heading", edit(CONTRIB, "./README.md#modules", "./README.md#modulez"), "broken anchor"),
    ("links", "link that leaves the repository", append(README, "\n[x](../../outside.md)\n"), "outside the repository"),
    ("numbers", "test count quoted wrongly in the module table", edit(README, "187 passed in the", "188 passed in the"), "quotes 188"),
    ("numbers", "Sigma rule count quoted wrongly", edit(README, "3 Sigma rules, 2 YARA rules", "4 Sigma rules, 2 YARA rules"), "quotes 4"),
    ("numbers", "number written as a word is checked too", edit(MOD_README, "2 YARA rules", "five YARA rules"), "quotes 5"),
    ("numbers", "bare number in root prose has no module context", append(README, "\nThis repository has 12 tests in total.\n"), "no module context"),
    ("numbers", "the drift that was fixed: stale corpus count in the cwe-078 module table", edit(CWE_README, "32 labelled raw log lines", "24 labelled raw log lines"),
     "quotes 24 but cwe-078-os-command-injection (tests/test_logs.jsonl) has 32"),
    ("numbers", "'N labelled' phrase that cannot be counted", edit(CWE_README, "32 labelled raw log lines", "32 labelled benign events"), "ambiguous, it labels 'benign events'"),
    ("numbers", "'N labelled' with nothing after it", append(CWE_README, "\nThe corpus has 32 labelled.\n"), "ambiguous, it labels nothing"),
    ("numbers", "labelled subset of the cases cannot be checked", append(CWE_README, "\nIt has 16 labelled benign cases.\n"), "ambiguous, it labels 'benign cases'"),
    ("numbers", "'N test cases' could mean tests or cases", append(CWE_TESTING, "\nThe suite has 32 test cases.\n"), "ambiguous (pytest tests or corpus cases?)"),
    ("numbers", "'N case tests' could mean tests or cases", append(CWE_TESTING, "\nThe 32 case tests all pass.\n"), "'32 case tests' is ambiguous"),
    ("numbers", "N/N cases quoted wrongly", edit(CWE_README, "`32/32 cases PASS`", "`32/31 cases PASS`"), "quotes 31"),
    ("numbers", "labelled count for a file named on the line is checked against that file", append(CWE_README, "\n`tests/test_logs.jsonl` has 31 labelled cases.\n"),
     "quotes 31"),
    ("pasted-output", "'collected N items' changed in the re-lumma block", edit(LUMMA_TESTING, "collected 187 items", "collected 188 items"), "says collected 188 but pytest collects 187"),
    ("pasted-output", "'N passed' changed in the re-lumma block", edit(LUMMA_TESTING, "= 187 passed in 1.41s =", "= 186 passed in 1.41s ="), "reports 186 results"),
    ("pasted-output", "'N passed' changed in the excerpt in the cwe-078 TESTING.md", edit(CWE_TESTING, "= 61 passed in 0.35s =", "= 60 passed in 0.35s ="), "reports 60 results"),
    ("pasted-output", "docs-checks block loses its suite marker", strip_suite_markers(LUMMA_TESTING, "docs-checks"), "names no suite"),
    ("pasted-output", "excerpt in cwe-078 TESTING.md loses its suite marker", strip_suite_markers(CWE_TESTING, "cwe-078-os-command-injection"), "names no suite"),
    ("pasted-output", "rootdir names another suite than the test paths", edit(LUMMA_TESTING, "rootdir: /repo/docs-checks", "rootdir: /repo/re-lumma-stealer"), "more than one suite"),
    ("command-tags", "command block loses its tag", edit(README, "# verified\npython -m pip install -r re-lumma-stealer/tests/requirements.txt -r cwe",
                                                         "python -m pip install -r re-lumma-stealer/tests/requirements.txt -r cwe"), "untagged"),
    ("command-run", "verified command exits non-zero", only_readme_with_failing_command, "exited 3"),
    ("command-run", "verified block that would run docs-checks is refused", verified_block_calls_docs_checks, "recurse"),
    ("module-table", "module folder missing from the table", drop_lines(README, "[`cwe-078-os-command-injection`](./cwe-078-os-command-injection/)"),
     "missing from the module table"),
    ("module-table", "table row for a folder that does not exist", append(README, "\n| [`cwe-999-phantom`](./cwe-999-phantom/) | x | x | x | x | x |\n"), "no such folder"),
    ("module-table", "module without TESTING.md", drop_file("re-lumma-stealer/TESTING.md"), "missing TESTING.md"),
    ("module-table", "module without a tests/ directory", drop_dir("cwe-078-os-command-injection/tests/"), "missing tests/ directory"),
    ("sigma-rules", "falsepositives removed", edit(RULE001, "\nfalsepositives:", "\nfalsepositivez:"), "falsepositives"),
    ("sigma-rules", "limits header removed", edit(RULE001, "SOURCE LIMITS", "SOURCE NOTES", None), "no limits section"),
    ("sigma-rules", "invalid level", edit(RULE001, "\nlevel: medium", "\nlevel: severe"), "'level'"),
    ("sigma-rules", "id that is not a UUID", edit(RULE001, "id: 721a50ab-c835-444a-a68f-2f34ffb9169a", "id: not-a-uuid"), "not a UUID"),
    ("sigma-rules", "status removed", edit(RULE001, "\nstatus: experimental", "\nstate: experimental"), "'status'"),
    ("yara-rules", "confidence meta removed", edit(YARA_CFG, 'confidence = "low"', 'confidenxe = "low"'), "'confidence'"),
    ("yara-rules", "header comment removed", lambda r: (r.set_text(YARA_CFG, r.text(YARA_CFG)[r.text(YARA_CFG).index("rule RE_"):]) or r), "header comment"),
    ("rule-ids-unique", "same Sigma id in a second file", lambda r: add_file("re-lumma-stealer/detection_rules/sigma/dup.yml", r.files[RULE001])(r), "already used"),
    ("rule-ids-unique", "same YARA rule name in a second file", lambda r: add_file("re-lumma-stealer/detection_rules/yara/dup.yar", r.files[YARA_CFG])(r), "already used"),
    ("exec-headers", "PE header in a fixture", add_file("re-lumma-stealer/tests/fixtures/payload.bin", b"MZ\x90\x00" + bytes(64)), "executable header"),
    ("exec-headers", "ELF header in a fixture", add_file("re-lumma-stealer/tests/fixtures/payload2.bin", b"\x7fELF" + bytes(64)), "executable header"),
    ("file-size", "file over the size limit", add_file("re-lumma-stealer/tests/fixtures/big.bin", b"a" * (d.MAX_FILE_BYTES + 1)), "over the"),
    ("network-indicators", "real IP address in a doc", append(README, "\nC2 at 45.33.32.156 observed.\n"), "45.33.32.156"),
    ("network-indicators", "defanged real IP address is still caught", append(README, "\nC2 at 45[.]33[.]32[.]156 observed.\n"), "45.33.32.156"),
    ("network-indicators", "real domain in a doc", append(README, "\nPanel at evil-c2-panel.com.\n"), "evil-c2-panel.com"),
    ("network-indicators", "defanged real domain is still caught", append(README, "\nSee hxxps://bad-host[.]xyz/login\n"), "bad-host.xyz"),
    ("network-indicators", "real IP address in a fixture", append("re-lumma-stealer/tests/fixtures/logs/rule001_cases.jsonl", '{"x": "45.33.32.156"}\n'), "45.33.32.156"),
    ("network-indicators", "real domain in iocs.csv", append("re-lumma-stealer/iocs.csv", "evil-c2-panel.com,domain,x,2026-11-22,none,n/a,x\n"), "evil-c2-panel.com"),
    ("placeholders", "placeholder marker left in a README", append(MOD_README, "\nContact: [ADD: name]\n"), "[ADD:"),
    ("placeholders", "placeholder marker left in an issue template", append(".github/ISSUE_TEMPLATE/config.yml", "# [ADD: x]\n"), "[ADD:"),
    ("intake", "a SIEM filled into field B1", intake_fill("B1", "Splunk 9.1"), "field B1 holds a value"),
    ("intake", "a value filled into field G3", intake_fill("G3", "none"), "field G3 holds a value"),
    ("intake", "an answer filled into A3 (a placeholder field)", intake_fill("A3", "phishing wave last week"), "field A3 holds a value"),
    ("intake", "a value in a field outside both lists", append(d.INTAKE_FILE, "\n**D1. Acceptable false positives per day** → 5 per day\n"), "field D1 holds a value"),
    ("intake", "required field deleted", drop_lines(d.INTAKE_FILE, "**E5."), "required field E5 is missing"),
    ("intake", "required A3 deleted", drop_lines(d.INTAKE_FILE, "**A3."), "required field A3 is missing"),
    ("intake", "rulebook missing from the repository", drop_file(d.INTAKE_FILE), "missing from the repository root"),
]

FAST_IDS = [f"{c}: {label}" for c, label, _, _ in MUTATIONS]


@pytest.mark.parametrize("check,label,mutate,expected", MUTATIONS, ids=FAST_IDS)
def test_mutation_turns_the_check_red(check, label, mutate, expected, repo, truth, repo_root):
    run = _runners(truth, repo_root)[check]
    if check != "command-run":  # the baseline for command-run is test_verified_commands_run_and_exit_zero (it is slow)
        assert run(repo.copy()) == [], f"baseline for {check} must be clean before mutating"
    mutated = mutate(repo.copy())
    problems = run(mutated)
    assert problems, f"{check}: the mutation '{label}' did not turn the check red"
    assert any(expected in p for p in problems), f"{check}: expected a problem containing {expected!r}, got:\n" + "\n".join(problems)


def test_every_check_has_a_mutation(truth, repo_root):
    covered = {c for c, *_ in MUTATIONS}
    assert covered == set(_runners(truth, repo_root)), "every check needs at least one mutation, and every mutation a known check"


def test_mutations_never_write_to_the_snapshot(repo):
    before = dict(repo.files)
    edit(README, "(./CONTRIBUTING.md)", "(./nope.md)", None)(repo.copy())
    assert repo.files == before
