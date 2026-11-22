"""
Detection tests for detection_rules/cmdi_sigma.yml

For each case in tests/test_logs.jsonl the suite:
  1. parses the RAW log line (Nginx combined, Apache vhost_combined or IIS W3C) into
     Sigma-style fields,
  2. checks the parser extracted the fields the case says it should (guards the corpus),
  3. evaluates the rule's own YAML against those fields and compares with expected_detected.

The evaluator below is a small, purpose-built Sigma subset: field modifiers contains /
startswith / endswith / re / cidr (+ "all"), selections as maps or lists of maps, and
conditions with and / or / not / parentheses / "1 of X*" / "all of X*" / "them".
Anything outside that subset raises NotImplementedError, so a rule change that uses
unsupported syntax fails loudly instead of passing silently. It complements, and does not
replace, converting the rule with sigma-cli / pySigma and testing in your SIEM.
"""
import fnmatch
import ipaddress
import json
import re
import uuid
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
RULE_PATH = ROOT / "detection_rules" / "cmdi_sigma.yml"
LOGS_PATH = Path(__file__).with_name("test_logs.jsonl")
TESTING_MD = ROOT / "TESTING.md"


# --------------------------------------------------------------------------- log parsing
_TAIL = (r'\[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<target>\S+) (?P<proto>HTTP/\d(?:\.\d)?)" '
         r'(?P<status>\d{3}) (?P<bytes>\d+|-) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"$')
NGINX_RE = re.compile(r'^(?P<c_ip>\S+) \S+ (?P<user>\S+) ' + _TAIL)
APACHE_VHOST_RE = re.compile(r'^(?P<vhost>\S+) (?P<c_ip>\S+) \S+ (?P<user>\S+) ' + _TAIL)


def _from_combined(rx, line):
    m = rx.match(line)
    if not m:
        raise ValueError(f"line does not match expected format: {line!r}")
    path, _, query = m["target"].partition("?")
    event = {
        "c-ip": m["c_ip"], "cs-method": m["method"], "cs-uri-stem": path,
        "cs-uri-query": query, "sc-status": m["status"], "cs-user-agent": m["ua"],
    }
    if "vhost" in m.groupdict():
        event["cs-host"] = m["vhost"]
    return event


def parse_iis_w3c(line, fields_header):
    names = fields_header.split()
    values = line.split(" ")
    if len(values) != len(names):
        raise ValueError(f"IIS line has {len(values)} values for {len(names)} fields: {line!r}")
    rec = dict(zip(names, values))
    return {
        "c-ip": rec["c-ip"], "cs-method": rec["cs-method"], "cs-uri-stem": rec["cs-uri-stem"],
        "cs-uri-query": "" if rec["cs-uri-query"] == "-" else rec["cs-uri-query"],
        "sc-status": rec["sc-status"], "cs-user-agent": rec.get("cs(User-Agent)", ""),
    }


def parse_log(case):
    fmt = case["log_format"]
    if fmt == "nginx_combined":
        return _from_combined(NGINX_RE, case["raw"])
    if fmt == "apache_vhost_combined":
        return _from_combined(APACHE_VHOST_RE, case["raw"])
    if fmt == "iis_w3c":
        return parse_iis_w3c(case["raw"], case["iis_fields"])
    raise ValueError(f"unknown log_format {fmt!r}")


# ----------------------------------------------------------------- Sigma subset evaluator
_OPS = {"contains", "startswith", "endswith", "re", "cidr"}


def _compare(op, value, expected):
    s, e = str(value), str(expected)
    if op == "equals":
        if any(ch in e for ch in "*?"):
            raise NotImplementedError("wildcards in plain equality are not supported by this evaluator")
        return s.lower() == e.lower()
    if op == "contains":
        return e.lower() in s.lower()
    if op == "startswith":
        return s.lower().startswith(e.lower())
    if op == "endswith":
        return s.lower().endswith(e.lower())
    if op == "re":
        return re.search(e, s) is not None  # Sigma regex is case-sensitive unless the rule says otherwise
    if op == "cidr":
        try:
            return ipaddress.ip_address(s) in ipaddress.ip_network(e, strict=False)
        except ValueError:
            return False
    raise NotImplementedError(op)


def _match_field(event, key, expected):
    field, *mods = key.split("|")
    require_all = "all" in mods
    ops = [m for m in mods if m != "all"]
    bad = [m for m in ops if m not in _OPS]
    if bad or len(ops) > 1:
        raise NotImplementedError(f"unsupported modifier(s) in {key!r}: {bad or ops}")
    op = ops[0] if ops else "equals"
    if field not in event:
        return False
    values = expected if isinstance(expected, list) else [expected]
    results = [_compare(op, event[field], v) for v in values]
    return all(results) if require_all else any(results)


def _eval_selection(event, selection):
    if isinstance(selection, dict):
        return all(_match_field(event, k, v) for k, v in selection.items())
    if isinstance(selection, list) and all(isinstance(s, dict) for s in selection):
        return any(_eval_selection(event, s) for s in selection)
    raise NotImplementedError("keyword (string-list) selections are not supported by this evaluator")


def _tokenize(condition):
    return re.findall(r"\(|\)|[^\s()]+", condition)


def evaluate_condition(condition, selections, event):
    tokens = _tokenize(condition)
    pos = 0
    cache = {}

    def sel(name):
        if name not in selections:
            raise KeyError(f"condition references unknown selection {name!r}")
        if name not in cache:
            cache[name] = _eval_selection(event, selections[name])
        return cache[name]

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def take():
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def parse_or():
        v = parse_and()
        while peek() == "or":
            take()
            r = parse_and()
            v = v or r
        return v

    def parse_and():
        v = parse_not()
        while peek() == "and":
            take()
            r = parse_not()
            v = v and r
        return v

    def parse_not():
        if peek() == "not":
            take()
            return not parse_not()
        return parse_atom()

    def parse_atom():
        tok = take()
        if tok == "(":
            v = parse_or()
            if take() != ")":
                raise ValueError("unbalanced parentheses in condition")
            return v
        if tok in ("1", "all") and peek() == "of":
            take()
            pattern = take()
            names = list(selections) if pattern == "them" else [n for n in selections if fnmatch.fnmatch(n, pattern)]
            if not names:
                raise ValueError(f"'{tok} of {pattern}' matches no selection")
            results = [sel(n) for n in names]
            return any(results) if tok == "1" else all(results)
        return sel(tok)

    value = parse_or()
    if pos != len(tokens):
        raise ValueError(f"unexpected trailing tokens in condition: {tokens[pos:]}")
    return value


def rule_matches(rule, event):
    detection = dict(rule["detection"])
    condition = detection.pop("condition")
    detection.pop("timeframe", None)
    return evaluate_condition(condition, detection, event)


# ---------------------------------------------------------------------------- fixtures
RULE = yaml.safe_load(RULE_PATH.read_text(encoding="utf-8"))
CASES = [json.loads(line) for line in LOGS_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]

REQUIRED_CATEGORIES = {          # category -> minimum number of cases
    "raw_payload": 4,
    "single_url_encoded": 4,
    "double_url_encoded": 2,
    "evasion": 2,
    "param_scope": 2,
    "scanner_filter_scope": 1,
    "legitimate_traffic": 3,
    "raw_ampersand_split": 2,
    "authorized_scanner": 1,
    "unrelated_endpoint": 1,
    "documented_gap": 8,
    "known_fp_needs_tuning": 1,
}
EXPECTED_CASES = 32              # update together with TESTING.md and the READMEs when a case is added
GAP_DESCRIPTION_PREFIXES = ("DOCUMENTED GAP", "PROBE, NOT AN EVASION")
REQUIRED_FORMATS = {"nginx_combined", "apache_vhost_combined", "iis_w3c"}


# ------------------------------------------------------------- one test per corpus case
@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_case(case, request):
    request.node.user_properties.append(("case", case))
    event = parse_log(case)

    for field, expected in case["expected_fields"].items():
        assert event[field] == expected, (
            f"parser mismatch on {field}: got {event[field]!r}, case expects {expected!r}")

    detected = rule_matches(RULE, event)
    verdict = "ALERT" if detected else "no alert"
    wanted = "ALERT" if case["expected_detected"] else "no alert"
    assert detected == case["expected_detected"], (
        f"{case['id']} ({case['technique']}): rule gave {verdict}, expected {wanted}. "
        f"query={event['cs-uri-query']!r} src={event['c-ip']}")


# ---------------------------------------------------------- coverage / integrity checks
def test_corpus_has_the_expected_number_of_unique_cases():
    ids = [c["id"] for c in CASES]
    assert len(CASES) == EXPECTED_CASES
    assert len(set(ids)) == len(ids), "duplicate case ids"
    required = {"id", "group", "category", "technique", "description", "log_format", "raw",
                "expected_fields", "expected_detected"}
    for c in CASES:
        assert required <= c.keys(), f"{c.get('id')} is missing {required - c.keys()}"
        assert c["group"] in ("true_positive", "benign")
        # A true positive alerts and benign traffic does not, except two documented categories: a gap is a real
        # payload that is not alerted, and a known false positive is benign traffic that is alerted (see the tests below).
        assert (c["group"] == "true_positive") == c["expected_detected"] or c["category"] in ("documented_gap", "known_fp_needs_tuning")


def test_documented_gap_cases_are_not_alerts_and_say_what_they_are():
    """A gap case must expect no alert (the rule is not changed to fit the test) and must say why it is a gap."""
    gaps = [c for c in CASES if c["category"] == "documented_gap"]
    assert gaps
    for c in gaps:
        assert c["group"] == "benign" and c["expected_detected"] is False, c["id"]
        assert c["description"].startswith(GAP_DESCRIPTION_PREFIXES), f"{c['id']} must start with one of {GAP_DESCRIPTION_PREFIXES}"
        if c["description"].startswith("PROBE"):
            assert "not a" in c["description"].lower(), f"{c['id']} must say it is not a command separator"
        else:
            assert ("would be a real attack only if" in c["description"] or "IS a real attack" in c["description"]
                    or "real payload" in c["description"]), f"{c['id']} must say when the gap becomes a real attack"


def test_known_false_positive_cases_alert_and_say_how_to_tune():
    """A known false positive is benign traffic the rule alerts on, pinned so the tuning advice stays visible."""
    fps = [c for c in CASES if c["category"] == "known_fp_needs_tuning"]
    assert fps
    for c in fps:
        assert c["group"] == "benign" and c["expected_detected"] is True, c["id"]
        assert c["description"].startswith("KNOWN FALSE POSITIVE"), c["id"]
        assert "removes" in c["description"] and "cost" in c["description"], f"{c['id']} must say how to tune and what it costs"


def test_rule_header_points_to_every_gap_and_false_positive_case_and_labels_the_placeholder():
    """The header must name every documented-gap and known-false-positive case, so it cannot drift from the corpus."""
    text = RULE_PATH.read_text(encoding="utf-8")
    header = text[:text.index("\ntitle:")]
    ids = [c["id"] for c in CASES if c["category"] in ("documented_gap", "known_fp_needs_tuning")]
    missing = [i for i in ids if i not in header]
    assert not missing, f"rule header does not mention: {missing}"
    assert "KNOWN COVERAGE GAPS" in header and "KNOWN FALSE POSITIVE" in header
    assert "PLACEHOLDER: 192.0.2.0/24 is RFC 5737 TEST-NET-1" in text, "the scanner range must stay a labelled placeholder"


def test_all_three_log_formats_are_exercised():
    assert {c["log_format"] for c in CASES} == REQUIRED_FORMATS


@pytest.mark.parametrize("category,minimum", sorted(REQUIRED_CATEGORIES.items()))
def test_required_category_is_covered(category, minimum):
    n = sum(1 for c in CASES if c["category"] == category)
    assert n >= minimum, f"category {category!r} has {n} case(s), requires at least {minimum}"


def test_rule_metadata_is_production_shaped():
    uuid.UUID(RULE["id"])
    assert RULE["level"] == "high"
    assert RULE["logsource"]["category"] == "webserver"
    assert RULE["falsepositives"], "rule must document false positives"
    assert {"attack.t1059", "attack.t1190"} <= set(RULE["tags"])
    assert "condition" in RULE["detection"]


def test_testing_md_lists_every_case_and_the_rule_id():
    text = TESTING_MD.read_text(encoding="utf-8")
    missing = [c["id"] for c in CASES if f"`{c['id']}`" not in text]
    assert not missing, f"TESTING.md does not list: {missing}"
    assert RULE["id"] in text


def test_evaluator_fails_loudly_on_unsupported_syntax():
    bad_rule = {"detection": {"selection": {"cs-uri-query|base64": "x"}, "condition": "selection"}}
    with pytest.raises(NotImplementedError):
        rule_matches(bad_rule, {"cs-uri-query": "x"})
