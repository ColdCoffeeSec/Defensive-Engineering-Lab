"""Mutation tests (BLUEPRINT.md section 4).

Each test breaks one rule or tool IN MEMORY (files on disk are never changed), re-runs the labelled
cases, and checks that the cases named for that break turn red. The test also asserts the EXACT set of
cases that turn red, so an unexpected side effect shows up as a failure and is documented here.

A mutation test passes when the break is caught. If a break is not caught, the test fails and the
suite has a blind spot.

M5 and M6 need yara-python (Python 3.12). `yara` is imported inside those tests, so on a machine
without it they fail with ImportError. They do not skip.
"""
import json
import types

import pytest
import yaml

import config_extract as cx
import gen_artifacts as ga
from conftest import LOG_DIR, ROOT, SIGMA_DIR, YARA_DIR
from sigma_eval import fires
from winevent import parse_event

R1 = SIGMA_DIR / "re_lumma_001_clickfix_user_powershell.yml"
R2 = SIGMA_DIR / "re_lumma_002_browser_store_read_nonbrowser.yml"


def cases(name):
    return [json.loads(line) for line in (LOG_DIR / name).read_text(encoding="utf-8").splitlines() if line.strip()]


def red_cases(rule_text, case_file):
    """IDs of cases where the (possibly mutated) rule gives a different verdict than expected_detected."""
    rule = yaml.safe_load(rule_text)
    return {c["id"] for c in cases(case_file) if fires(rule, parse_event(c["raw"])) is not c["expected_detected"]}


def mutate(text, old, new):
    assert text.count(old) == 1, f"mutation anchor not found exactly once: {old!r}"
    return text.replace(old, new)


# --------------------------------------------------------------------------- baselines
def test_baseline_unmutated_rules_have_no_red_cases():
    assert red_cases(R1.read_text(encoding="utf-8"), "rule001_cases.jsonl") == set()
    assert red_cases(R2.read_text(encoding="utf-8"), "rule002_cases.jsonl") == set()


# --------------------------------------------------------------------------- Sigma mutations
def test_m1_drop_encoded_variant_from_rule_001():
    text = mutate(R1.read_text(encoding="utf-8"), "selection_ps_encoded or ", "")
    red = red_cases(text, "rule001_cases.jsonl")
    named = {"R1-P01", "R1-P02", "R1-P03", "R1-P04", "R1-P05", "R1-P06"}  # every Base64 positive
    assert named <= red
    assert red == named


def test_m2_remove_parent_filter_from_rule_001():
    text = mutate(R1.read_text(encoding="utf-8"), "        selection_parent and (\n", "        (\n")
    red = red_cases(text, "rule001_cases.jsonl")
    named = {"R1-N01", "R1-N02", "R1-N03", "R1-N04"}  # benign near-misses with a non-explorer parent
    assert named <= red
    assert red == named | {"R1-G02"}  # the documented gap (cmd.exe parent) also starts to alert


def test_m3_remove_browser_filter_from_rule_002():
    text = mutate(R2.read_text(encoding="utf-8"), " and not filter_browser", "")
    red = red_cases(text, "rule002_cases.jsonl")
    named = {"R2-N01", "R2-N02", "R2-N03", "R2-N04", "R2-N05", "R2-N06", "R2-N07"}  # browsers and updaters
    assert {"R2-N05", "R2-N06"} <= red  # the browser-updater cases named in the blueprint
    assert named <= red
    assert red == named | {"R2-G01", "R2-G02"}  # the two filter-evasion gaps also start to alert


# --------------------------------------------------------------------------- extractor mutation
def _load_mutated_extractor(old, new):
    source = (ROOT / "tools" / "config_extract.py").read_text(encoding="utf-8")
    module = types.ModuleType("config_extract_mutated")
    exec(compile(mutate(source, old, new), "config_extract_mutated", "exec"), module.__dict__)
    return module


def _round_trip_ok(module):
    try:
        return module.extract_config_json(ga.build_blob()) == ga.PLAINTEXT_CONFIG
    except Exception:  # any failure to recover the config counts as a red round trip
        return False


def test_m4_change_key_length_in_extractor():
    assert _round_trip_ok(cx) is True  # baseline
    assert _round_trip_ok(_load_mutated_extractor("KEY_LEN = 32", "KEY_LEN = 24")) is False


# --------------------------------------------------------------------------- YARA mutations
def _yara_red(mutated_text, fixtures):
    import yara  # imported here on purpose: no yara means a loud failure, not a skip

    try:
        rules = yara.compile(source=mutated_text)
    except yara.SyntaxError as exc:  # a mutation that breaks compilation is caught, but note why
        return {"__compile_error__": str(exc)}
    return {name for name, (data, expected) in fixtures.items() if bool(rules.match(data=data)) is not expected}


def test_m5_remove_one_indicator_from_config_strings_rule():
    original = (YARA_DIR / "re_lumma_config_strings.yar").read_text(encoding="utf-8")
    assert _yara_red(original, ga.config_strings_fixtures()) == set()  # baseline
    text = mutate(original, '        $ver40    = "ver=4.0" ascii wide\n', "")
    text = mutate(text, "4 of ($cmd_*, $ver40)", "4 of ($cmd_*)")
    red = _yara_red(text, ga.config_strings_fixtures())
    assert "__compile_error__" not in red, red
    named = {"cfg_positive_all", "cfg_positive_uid_variant", "cfg_positive_lid_variant"}
    assert red == named


def test_m6_weaken_setup_condition_to_any_of():
    original = (YARA_DIR / "re_lumma_chacha_setup.yar").read_text(encoding="utf-8")
    assert _yara_red(original, ga.setup_fixtures()) == set()  # baseline
    text = mutate(original, "all of them", "any of them")
    red = _yara_red(text, ga.setup_fixtures())
    assert red == {"setup_negative_constant_only", "setup_negative_winhttp_only", "setup_negative_constant_and_dll"}
