"""Tests for the Sigma rules in detection_rules/sigma/.

What these tests show: the rules' logic matches the labelled synthetic cases, benign near-misses do
not alert, and documented gaps stay documented. What they do NOT show: a detection rate or a
false-positive rate. All cases are synthetic (ENVIRONMENT_ASSUMPTIONS.md section 6).

Evaluation uses tests/sigma_eval.py, a small Sigma subset that raises on unsupported syntax. Each rule
is also parsed with pySigma, and the pinned pySigma version is asserted against requirements.txt.
"""
import importlib.metadata
import json
import re
import uuid

import pytest
from sigma.collection import SigmaCollection

import build_cases
import gen_benign
from conftest import LOG_DIR, REQUIREMENTS, SIGMA_DIR
from sigma_eval import fires, load_rule
from winevent import parse_event

RULE_FILES = {
    "re_lumma_001": SIGMA_DIR / "re_lumma_001_clickfix_user_powershell.yml",
    "re_lumma_002": SIGMA_DIR / "re_lumma_002_browser_store_read_nonbrowser.yml",
}
CASE_FILES = {"re_lumma_001": LOG_DIR / "rule001_cases.jsonl", "re_lumma_002": LOG_DIR / "rule002_cases.jsonl"}
CASE_KEYS = {"id", "group", "category", "technique", "description", "log_format", "raw", "expected_fields", "expected_detected"}


def load_cases(group):
    return [json.loads(line) for line in CASE_FILES[group].read_text(encoding="utf-8").splitlines() if line.strip()]


ALL_CASES = [(g, c) for g in CASE_FILES for c in load_cases(g)]


@pytest.fixture(scope="module")
def rules():
    return {name: load_rule(path) for name, path in RULE_FILES.items()}


# --------------------------------------------------------------------------- rule hygiene
def test_pysigma_version_matches_pin(record_property):
    pinned = re.search(r"^pysigma==(\S+)", REQUIREMENTS.read_text(encoding="utf-8"), re.M | re.I).group(1)
    installed = importlib.metadata.version("pysigma")
    record_property("pysigma_version", installed)
    assert installed == pinned


@pytest.mark.parametrize("name", RULE_FILES)
def test_rule_parses_with_pysigma_and_has_required_metadata(name):
    text = RULE_FILES[name].read_text(encoding="utf-8")
    collection = SigmaCollection.from_yaml(text)
    assert len(collection.rules) == 1
    rule = collection.rules[0]
    assert rule.errors == []
    assert rule.falsepositives, "every rule needs falsepositives"
    assert rule.level is not None
    assert rule.status is not None
    uuid.UUID(str(rule.id))
    # Source-limits note and the analyst-derived marker must be in the rule file header.
    assert "SOURCE LIMITS" in text
    assert "[A]" in text or "ANALYST-DERIVED" in text.upper()


def test_rule_ids_are_unique():
    ids = [load_rule(p)["id"] for p in RULE_FILES.values()]
    assert len(ids) == len(set(ids))


def test_rule_002_declares_that_it_cannot_fire_in_the_reference_environment():
    text = RULE_FILES["re_lumma_002"].read_text(encoding="utf-8")
    assert "CANNOT FIRE IN THE REFERENCE ENVIRONMENT" in text


# --------------------------------------------------------------------------- fixtures
def test_committed_case_files_match_the_builder():
    for name, cases in build_cases.build_all().items():
        committed = [json.loads(line) for line in (LOG_DIR / name).read_text(encoding="utf-8").splitlines() if line.strip()]
        assert committed == cases, f"{name} is out of date: run tests/fixtures/build_cases.py"


@pytest.mark.parametrize("group,case", ALL_CASES, ids=[c["id"] for _, c in ALL_CASES])
def test_case_schema_and_parsed_fields(group, case):
    assert set(case) == CASE_KEYS
    assert case["group"] == group
    assert case["log_format"] == "windows_event_xml"
    event = parse_event(case["raw"])
    for field, expected in case["expected_fields"].items():
        assert event.get(field) == expected, f"{case['id']}: parser produced {event.get(field)!r} for {field}"


@pytest.mark.parametrize("group", CASE_FILES)
def test_required_categories_and_tp_and_benign_present(group):
    cases = load_cases(group)
    categories = {c["category"] for c in cases}
    required = {
        "re_lumma_001": {"clickfix-encoded", "clickfix-cradle", "clickfix-mshta", "benign-near-miss", "documented-gap"},
        "re_lumma_002": {"browser-store-read", "benign-near-miss", "known-fp-needs-tuning", "documented-gap"},
    }[group]
    assert required <= categories, f"missing categories: {sorted(required - categories)}"
    assert any(c["expected_detected"] for c in cases), "need at least one true-positive case"
    assert any(not c["expected_detected"] and c["category"] == "benign-near-miss" for c in cases), "need a benign case"


# --------------------------------------------------------------------------- detection logic
@pytest.mark.parametrize("group,case", ALL_CASES, ids=[c["id"] for _, c in ALL_CASES])
def test_rule_against_case(rules, group, case, record_property):
    record_property("category", case["category"])
    record_property("expected_detected", case["expected_detected"])
    event = parse_event(case["raw"])
    assert fires(rules[group], event) is case["expected_detected"], case["description"]


@pytest.mark.parametrize("group", CASE_FILES)
def test_rule_does_not_fire_on_the_other_rules_events(rules, group):
    """A rule must not evaluate events from a different log source (logsource gating)."""
    other = "re_lumma_002" if group == "re_lumma_001" else "re_lumma_001"
    for case in load_cases(other):
        assert fires(rules[group], parse_event(case["raw"])) is False, case["id"]


# --------------------------------------------------------------------------- benign corpus
def test_benign_corpus_counts_are_fixed():
    assert len(gen_benign.rule001_events()) == gen_benign.RULE001_COUNT == 300
    assert len(gen_benign.rule002_events()) == gen_benign.RULE002_COUNT == 200


def test_benign_corpus_is_deterministic():
    assert gen_benign.rule001_events() == gen_benign.rule001_events()
    assert gen_benign.rule002_events() == gen_benign.rule002_events()


def test_rule_001_silent_on_synthetic_benign_corpus(rules):
    alerts = [e for e in gen_benign.rule001_events() if fires(rules["re_lumma_001"], parse_event(e))]
    assert alerts == []


def test_rule_002_silent_on_synthetic_benign_corpus(rules):
    alerts = [e for e in gen_benign.rule002_events() if fires(rules["re_lumma_002"], parse_event(e))]
    assert alerts == []
