"""Sensitivity tests for the documented-gap and known-false-positive cases.

Each test edits an IN-MEMORY COPY of the rule so it covers the case, and checks that exactly that case changes
verdict. The rule file on disk is never changed, and the gap cases stay expected_detected false (or true, for a
known false positive) in the corpus.

What this shows: each probe really exercises the pattern its description names, and does not pass for an unrelated
reason such as a parse problem. It is NOT a recommendation to close the gaps. For the probes that are not command
separators (%c0%af, %09, %00) there is nothing to close; they are here so the blind-spot analysis is on record.
"""
import copy

import pytest

from test_rule import CASES, RULE, parse_log, rule_matches

# case id, selection in the rule, field in that selection, value added to its list
GAP_CLOSERS = [
    ("B-09", "selection_payload_double_encoded", "cs-uri-query|contains", "%25253b"),     # triple-encoded ;
    ("B-10", "selection_payload_raw", "cs-uri-query|contains", "；"),               # U+FF1B fullwidth ; (literal)
    ("B-11", "selection_payload_encoded", "cs-uri-query|contains", "%ef%bc%9b"),        # U+FF1B as percent-encoded UTF-8
    ("B-12", "selection_payload_encoded", "cs-uri-query|contains", "%c0%af"),           # overlong UTF-8 '/'
    ("B-13", "selection_payload_encoded", "cs-uri-query|contains", "%09"),              # tab
    ("B-14", "selection_payload_encoded", "cs-uri-query|contains", "%00"),              # NUL
    ("B-15", "selection_endpoint", "cs-uri-stem|endswith", "/ping.php"),                # other endpoint path
]


def verdicts(rule):
    return {c["id"]: rule_matches(rule, parse_log(c)) for c in CASES}


BASELINE = verdicts(RULE)


def flipped(mutated_rule):
    after = verdicts(mutated_rule)
    return {cid for cid in after if after[cid] != BASELINE[cid]}


@pytest.mark.parametrize("case_id,selection,field,value", GAP_CLOSERS, ids=[g[0] for g in GAP_CLOSERS])
def test_adding_the_missing_pattern_flips_only_that_gap_case(case_id, selection, field, value):
    mutated = copy.deepcopy(RULE)
    mutated["detection"][selection][field].append(value)
    assert BASELINE[case_id] is False, "the gap case must not alert on the rule as it is"
    assert flipped(mutated) == {case_id}
    assert verdicts(mutated)[case_id] is True


def test_every_documented_gap_case_has_a_sensitivity_test_or_is_the_older_scope_gap():
    covered = {g[0] for g in GAP_CLOSERS}
    gaps = {c["id"] for c in CASES if c["category"] == "documented_gap"}
    assert gaps - covered == {"B-08"}, "B-08 (other path, other parameter name) is the original scope gap"


def test_tuning_away_the_known_false_positive_also_silences_real_semicolon_injections():
    """B-16 is the known false positive. Removing ';' from the raw list (the documented tuning) silences it, and the
    test shows the cost: TP-01 and TP-16, which are real ';' injections, stop alerting too. Nothing else changes."""
    mutated = copy.deepcopy(RULE)
    mutated["detection"]["selection_payload_raw"]["cs-uri-query|contains"].remove(";")
    assert BASELINE["B-16"] is True, "the known false positive must alert on the rule as it is"
    assert flipped(mutated) == {"B-16", "TP-01", "TP-16"}
    assert verdicts(mutated)["B-16"] is False
