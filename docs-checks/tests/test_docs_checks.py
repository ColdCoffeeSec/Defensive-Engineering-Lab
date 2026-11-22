"""The documentation checks, run on the real repository.

Each test calls one pure check from docs_lib.py. test_docs_mutations.py proves every check can fail.
"""
import posixpath

import pytest

import docs_lib as d


def assert_clean(problems):
    assert problems == [], "\n" + "\n".join(problems)


def test_links_and_anchors_resolve(repo):
    assert_clean(d.check_links(repo))


def test_quoted_counts_match_what_pytest_collects(repo, truth):
    assert_clean(d.check_numbers(repo, truth))


def test_pasted_pytest_output_matches_what_pytest_collects(repo, truth):
    assert_clean(d.check_pasted_pytest_output(repo, truth))


def test_every_command_block_is_tagged(repo):
    assert_clean(d.check_command_tags(repo))


def test_verified_commands_run_and_exit_zero(repo, repo_root):
    assert_clean(d.check_verified_commands(repo, lambda script: d.run_bash(script, repo_root)))


def test_module_table_matches_folders_and_required_files(repo):
    assert_clean(d.check_module_table(repo))


def test_sigma_rule_files_have_required_fields_and_limits_header(repo):
    assert_clean(d.check_sigma_rules(repo))


def test_yara_rule_files_have_required_meta_and_header(repo):
    assert_clean(d.check_yara_rules(repo))


def test_rule_ids_and_names_are_unique_across_modules(repo):
    assert_clean(d.check_rule_ids_unique(repo))


def test_no_executable_headers_anywhere(repo):
    assert_clean(d.check_no_executable_headers(repo))


def test_no_file_over_the_size_limit(repo):
    assert_clean(d.check_file_sizes(repo))


def test_no_real_network_indicators_in_docs_and_fixtures(repo):
    assert_clean(d.check_network_indicators(repo))


def test_no_placeholders_left_in_docs(repo):
    assert_clean(d.check_no_placeholders_in_docs(repo))


def test_intake_rulebook_in_repo_is_an_unfilled_template(repo):
    assert_clean(d.check_intake_file(repo))


# --------------------------------------------------------------------------- the checks must not pass vacuously
def test_checks_look_at_something(repo, truth):
    modules = repo.modules()
    assert {"cwe-078-os-command-injection", "re-lumma-stealer"} <= set(modules)
    assert len(d.sigma_rule_paths(repo)) >= 4 and len(d.yara_rule_paths(repo)) >= 2
    assert len(d.indicator_scan_paths(repo)) >= 10
    assert all(truth[m]["tests"] > 0 for m in modules)
    readmes = [p for p in repo.md_files() if posixpath.basename(p) == "README.md"]
    assert len(readmes) >= 3
    verified = [(p, f) for p, f in d.command_blocks(repo) if d.TAG_VERIFIED.match(d._first_line(f))]
    assert {"README.md", "re-lumma-stealer/README.md"} <= {p for p, _ in verified}, "root and module READMEs need a verified command"
    assert sum(len(list(d.extract_links(repo.text(p)))) for p in repo.md_files()) >= 20
    # the count checks look at real prose and real pasted output, and the pasted blocks cover every suite
    assert {"cwe-078-os-command-injection", "re-lumma-stealer", "docs-checks"} <= set(truth)
    assert all(truth[m]["cases"] > 0 for m in ("cwe-078-os-command-injection", "re-lumma-stealer"))
    blocks = list(d.pasted_pytest_blocks(repo))
    assert len(blocks) >= 4
    named = set()
    for _, fence in blocks:
        named |= d.suites_named_in_block("\n".join(fence["lines"]), set(truth))
    assert {"cwe-078-os-command-injection", "re-lumma-stealer", "docs-checks"} <= named


def test_version_strings_are_not_mistaken_for_ip_addresses():
    text = "UA Mozilla/5.0 Chrome/119.0.0.0 Safari/537.36 and Windows-Update-Agent/10.0.10011.16384, address 203.0.113.9."
    assert d._scan_for_indicators("x.md", text) == []


# --------------------------------------------------------------------------- the intake check must not be too strict either
def _rewrite_field(repo, field, value):
    import re
    text = repo.text(d.INTAKE_FILE)
    new, n = re.subn(rf"^(\*\*{field}\. .*?\*\*\s*→\s*).*$", rf"\g<1>{value}", text, count=1, flags=re.M)
    assert n == 1, field
    repo.set_text(d.INTAKE_FILE, new)


@pytest.mark.parametrize("field", d.INTAKE_FIXED_ANSWERS)
def test_intake_allows_a_fixed_answer_to_change(repo, field):
    mutated = repo.copy()
    _rewrite_field(mutated, field, "a different fixed answer for this repository")
    assert d.check_intake_file(mutated) == []


def test_intake_accepts_placeholders_with_or_without_backticks(repo):
    plain = repo.copy()
    plain.set_text(d.INTAKE_FILE, plain.text(d.INTAKE_FILE).replace("`[ADD:", "[ADD:").replace("]`", "]"))
    assert d.check_intake_file(plain) == []


def test_intake_fixed_and_required_lists_do_not_overlap_and_cover_the_expected_fields():
    assert not set(d.INTAKE_FIXED_ANSWERS) & set(d.INTAKE_REQUIRED)
    assert "A3" in d.INTAKE_REQUIRED and {"A1", "A2", "A4", "A5", "E1", "E2", "E3", "E4", "G1", "H1", "H2", "H3"} == set(d.INTAKE_FIXED_ANSWERS)


# --------------------------------------------------------------------------- the count checks must not be too strict either
# A correct document must still pass. These run on small in-memory repositories with a made-up truth.
FAKE_TRUTH = {
    "cwe-x": {"tests": 61, "cases": 32, "sigma": 1, "yara": 0, "corpus": {"tests/test_logs.jsonl": 32}},
    "re-y": {"tests": 175, "cases": 54, "sigma": 3, "yara": 2,
             "corpus": {"tests/fixtures/logs/a.jsonl": 25, "tests/fixtures/logs/b.jsonl": 23, "tests/fixtures/logs/c.jsonl": 6}},
    "docs-z": {"tests": 72, "cases": 0, "sigma": 0, "yara": 0, "corpus": {}},
}


def snapshot(files):
    return d.Repo({path: text.encode("utf-8") for path, text in files.items()})


@pytest.mark.parametrize("sentence", [
    "| [tests/test_logs.jsonl](./tests/test_logs.jsonl) | 32 labelled raw log lines in three formats |",
    "32 labelled cases in the corpus.",
    "32 labeled cases, American spelling.",
    "thirty-two is not a number word here, but 32 labelled log lines are.",
    "Add one labelled case per bypass.",
    "**Corpus:** `tests/test_logs.jsonl`: 32 cases (16 true positives, 16 benign) in three log formats",
    "Expected result: `32/32 cases PASS` and `61 passed`.",
    "The suite has 61 tests and 1 Sigma rule.",
    "It has one test for each gap.",
    "Run 5 test files at a time.",
    "A rule id such as 002 is not a count: Rule 002 cases are listed below.",
])
def test_prose_counts_allow_a_correct_sentence(sentence):
    ok = snapshot({"cwe-x/README.md": sentence + "\n"})
    assert d.check_numbers(ok, FAKE_TRUTH) == []


def test_prose_counts_allow_the_count_of_the_one_file_a_line_names():
    ok = snapshot({"re-y/README.md": "`tests/fixtures/logs/c.jsonl` holds 6 labelled cases, and all 54 cases are in three files.\n"})
    # the line names one corpus file, so both numbers are compared with that file (6): the 54 is wrong on this line
    assert len(d.check_numbers(ok, FAKE_TRUTH)) == 1
    ok = snapshot({"re-y/README.md": "`c.jsonl` holds 6 labelled cases.\n\nAll 54 labelled cases are in three files.\n",
                   "re-y/TESTING.md": "175 tests and 5 rules pass.\n"})
    assert d.check_numbers(ok, FAKE_TRUTH) == []


def test_prose_counts_ignore_numbers_inside_fenced_blocks():
    text = "```text\n99 labelled raw log lines, 99 cases, 99 tests, 99 passed\n```\n"
    assert d.check_numbers(snapshot({"cwe-x/TESTING.md": text}), FAKE_TRUTH) == []


def test_prose_counts_apply_to_a_docs_suite_too():
    assert d.check_numbers(snapshot({"docs-z/README.md": "72 tests run here.\n"}), FAKE_TRUTH) == []
    bad = d.check_numbers(snapshot({"docs-z/README.md": "71 tests run here.\n"}), FAKE_TRUTH)
    assert any("quotes 71" in p for p in bad)


def pytest_block(suite, collected=61, summary="61 passed in 0.35s", rootdir=True, paths=True, extra=""):
    lines = ["============================= test session starts =============================="]
    if rootdir:
        lines.append(f"rootdir: /repo/{suite}")
    lines.append(f"collecting ... collected {collected} items" if collected is not None else "")
    lines.append(f"{suite}/tests/test_a.py::test_one PASSED [100%]" if paths else "test_a.py::test_one PASSED [100%]")
    if extra:
        lines.append(extra)
    lines.append(f"============================== {summary} ==============================")
    return "```\n" + "\n".join(lines) + "\n```\n"


@pytest.mark.parametrize("label,block", [
    ("rootdir and paths", pytest_block("cwe-x")),
    ("rootdir only, no test paths", pytest_block("cwe-x", paths=False)),
    ("test paths only, no rootdir (an excerpt)", pytest_block("cwe-x", rootdir=False, collected=None)),
    ("collect-only -q form", pytest_block("cwe-x", collected=None, summary="61 tests collected in 0.15s\n61 passed in 1s")),
    ("some failed", pytest_block("cwe-x", summary="3 failed, 58 passed in 0.5s")),
    ("some deselected", pytest_block("cwe-x", summary="1 passed, 60 deselected in 0.1s")),
    ("failed, skipped and a warning", pytest_block("cwe-x", summary="1 failed, 58 passed, 2 skipped, 3 warnings in 0.5s")),
    ("a block with no count line is not looked at", "```bash\npython -m pytest --version\n```\n"),
])
def test_pasted_output_allows_a_correct_block(label, block):
    assert d.check_pasted_pytest_output(snapshot({"cwe-x/TESTING.md": block}), FAKE_TRUTH) == []


def test_pasted_output_allows_one_block_per_suite_in_one_file():
    text = pytest_block("cwe-x") + "\ntext\n\n" + pytest_block("re-y", collected=175, summary="175 passed in 1.36s")
    assert d.check_pasted_pytest_output(snapshot({"re-y/TESTING.md": text}), FAKE_TRUTH) == []


def test_pasted_output_does_not_read_a_count_out_of_a_test_id():
    # a parametrized test id may contain "61 passed" or "collected 7 items"; it is a name, not a summary
    block = pytest_block("cwe-x", extra="cwe-x/tests/test_a.py::test_it[Expected `32/32 cases PASS` and `99 passed`; collected 7 items] PASSED [ 50%]")
    assert d.check_pasted_pytest_output(snapshot({"cwe-x/TESTING.md": block}), FAKE_TRUTH) == []
    only_ids = "```\ncwe-x/tests/test_a.py::test_it[`99 passed`] PASSED\n```\n"
    assert list(d.pasted_pytest_blocks(snapshot({"cwe-x/TESTING.md": only_ids}))) == []


def test_pasted_output_looks_at_fences_only():
    # prose counts are the other check's job; a bare "99 passed" line outside a fence is not read here
    assert d.check_pasted_pytest_output(snapshot({"cwe-x/TESTING.md": "99 passed in prose\n"}), FAKE_TRUTH) == []


def test_pasted_output_names_the_suite_it_cannot_identify():
    bad = d.check_pasted_pytest_output(snapshot({"cwe-x/TESTING.md": pytest_block("cwe-x", rootdir=False, paths=False)}), FAKE_TRUTH)
    assert len(bad) == 1 and "names no suite" in bad[0]
