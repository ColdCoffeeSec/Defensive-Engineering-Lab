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
