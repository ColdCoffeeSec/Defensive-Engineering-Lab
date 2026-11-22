"""Tests for the YARA rules in detection_rules/yara/.

Fixtures are SYNTHETIC byte strings: filler with the rule's own indicator strings dropped in. They are
non-executable. A pass shows the rule logic matches the labelled fixtures. It is not a detection rate,
and it says nothing about real samples: no sample is used (ENVIRONMENT_ASSUMPTIONS.md section 3).

The rules do not use the `pe` module, because a `pe` condition cannot be tested on synthetic filler.
test_rules_do_not_use_pe_module guards that. If a rule ever needs `pe`, it can only be validated in an
offline local run, and TESTING.md must say so.

Requires yara-python. It has no Windows wheel for Python 3.14: run this file on Python 3.12 (CI or a container).
"""
import importlib.metadata
import re

import pytest
import yara

import gen_artifacts as ga
from conftest import REQUIREMENTS, YARA_DIR

CONFIG_RULE = YARA_DIR / "re_lumma_config_strings.yar"
SETUP_RULE = YARA_DIR / "re_lumma_chacha_setup.yar"


def compile_text(text):
    return yara.compile(source=text)


def matches(rules, data):
    return [m.rule for m in rules.match(data=data)]


@pytest.fixture(scope="module")
def config_rules():
    return compile_text(CONFIG_RULE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def setup_rules():
    return compile_text(SETUP_RULE.read_text(encoding="utf-8"))


def test_yara_python_version_matches_pin(record_property):
    pinned = re.search(r"^yara-python==(\S+)", REQUIREMENTS.read_text(encoding="utf-8"), re.M | re.I).group(1)
    installed = importlib.metadata.version("yara-python")
    record_property("yara_python_version", installed)
    assert installed == pinned


@pytest.mark.parametrize("path", [CONFIG_RULE, SETUP_RULE], ids=lambda p: p.name)
def test_rule_file_compiles_without_warnings_and_declares_its_basis(path):
    text = path.read_text(encoding="utf-8")
    # error_on_warning makes YARA reject conditions it can prove are always false (for example "4 of" three strings).
    yara.compile(source=text, error_on_warning=True)
    assert 'basis = "analyst-derived' in text
    assert 'confidence = "low"' in text
    assert "[A]" in text


@pytest.mark.parametrize("path", [CONFIG_RULE, SETUP_RULE], ids=lambda p: p.name)
def test_rules_do_not_use_pe_module(path):
    text = path.read_text(encoding="utf-8")
    assert 'import "pe"' not in text
    assert "pe." not in re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def test_fixtures_are_non_executable():
    for fixtures in (ga.config_strings_fixtures(), ga.setup_fixtures()):
        for name, (data, _) in fixtures.items():
            assert not data.startswith((b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe")), name


@pytest.mark.parametrize("name", sorted(ga.config_strings_fixtures()))
def test_config_strings_rule_against_fixture(config_rules, name):
    data, expected = ga.config_strings_fixtures()[name]
    assert (matches(config_rules, data) == ["RE_Lumma_C2_Protocol_Strings"]) is expected, name


@pytest.mark.parametrize("name", sorted(ga.setup_fixtures()))
def test_setup_rule_against_fixture(setup_rules, name):
    data, expected = ga.setup_fixtures()[name]
    assert (matches(setup_rules, data) == ["RE_Lumma_ChaCha_WinHttp_Cooccurrence"]) is expected, name


def test_each_rule_ignores_the_other_rules_positives(config_rules, setup_rules):
    for name, (data, expected) in ga.config_strings_fixtures().items():
        if expected:
            assert matches(setup_rules, data) == [], name
    for name, (data, expected) in ga.setup_fixtures().items():
        if expected:
            assert matches(config_rules, data) == [], name


def test_rules_ignore_the_synthetic_config_blob(config_rules, setup_rules):
    blob = ga.build_blob()
    assert matches(config_rules, blob) == []
    assert matches(setup_rules, blob) == []


def test_fixture_sets_are_deterministic():
    assert ga.config_strings_fixtures() == ga.config_strings_fixtures()
    assert ga.setup_fixtures() == ga.setup_fixtures()
