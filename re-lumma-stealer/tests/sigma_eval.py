"""A small, purpose-built Sigma evaluator for this module's rules.

Supported: field modifiers contains, startswith, endswith, re and all; selections as a map
(AND of fields) or a list of maps (OR); conditions with and, or, not, parentheses, "1 of X*",
"all of X*" and "them". Anything else raises UnsupportedSigma, so a rule edit that uses syntax
this evaluator does not know fails loudly instead of passing silently.

This evaluator checks rule LOGIC against fixtures. It does not replace converting the rule with
pySigma for your SIEM and testing there (ENVIRONMENT_ASSUMPTIONS.md section 1: no vendor query
language is assumed). test_sigma_rules.py also parses each rule with pySigma.

Matching follows Sigma defaults: plain string comparison is case-insensitive; "re" is a regular
expression search and is case-sensitive unless the pattern sets (?i).
"""
import fnmatch
import re

import yaml


class UnsupportedSigma(NotImplementedError):
    pass


_MODIFIERS = {"contains", "startswith", "endswith", "re", "all"}


def load_rule(path_or_text):
    text = path_or_text.read_text(encoding="utf-8") if hasattr(path_or_text, "read_text") else path_or_text
    return yaml.safe_load(text)


def _match_one(kind, actual, expected):
    if kind == "re":
        return re.search(str(expected), str(actual)) is not None
    a, e = str(actual).lower(), str(expected).lower()
    if "*" in e or "?" in e:
        raise UnsupportedSigma(f"wildcards in values are not supported: {expected!r}")
    return {"contains": e in a, "startswith": a.startswith(e), "endswith": a.endswith(e), "equals": a == e}[kind]


def _eval_field(event, key, expected):
    field, *mods = key.split("|")
    unknown = set(mods) - _MODIFIERS
    if unknown:
        raise UnsupportedSigma(f"unsupported modifier(s) {sorted(unknown)} in {key!r}")
    kinds = [m for m in mods if m != "all"] or ["equals"]
    if len(kinds) != 1:
        raise UnsupportedSigma(f"more than one match modifier in {key!r}")
    if expected is None:
        raise UnsupportedSigma(f"null value in {key!r}")
    if field not in event:
        return False
    values = expected if isinstance(expected, list) else [expected]
    hits = [_match_one(kinds[0], event[field], v) for v in values]
    return all(hits) if "all" in mods else any(hits)


def _eval_selection(event, selection):
    if isinstance(selection, dict):
        return all(_eval_field(event, k, v) for k, v in selection.items())
    if isinstance(selection, list) and all(isinstance(s, dict) for s in selection):
        return any(_eval_selection(event, s) for s in selection)
    raise UnsupportedSigma("keyword-only selections are not supported")


class _Condition:
    def __init__(self, text, names, resolve):
        self.tokens = re.findall(r"\(|\)|[^\s()]+", text)
        self.pos, self.names, self.resolve = 0, names, resolve

    def _peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _take(self):
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def parse(self):
        value = self._or()
        if self._peek() is not None:
            raise UnsupportedSigma(f"unexpected token {self._peek()!r} in condition")
        return value

    def _or(self):
        value = self._and()
        while self._peek() == "or":
            self._take()
            right = self._and()  # evaluate both sides: keeps parsing simple
            value = value or right
        return value

    def _and(self):
        value = self._not()
        while self._peek() == "and":
            self._take()
            right = self._not()
            value = value and right
        return value

    def _not(self):
        if self._peek() == "not":
            self._take()
            return not self._not()
        return self._atom()

    def _atom(self):
        tok = self._take()
        if tok == "(":
            value = self._or()
            if self._peek() != ")":
                raise UnsupportedSigma("missing closing parenthesis")
            self._take()
            return value
        if tok in ("1", "all") and self._peek() == "of":
            self._take()
            pattern = self._take()
            chosen = self.names if pattern == "them" else fnmatch.filter(self.names, pattern)
            if not chosen:
                raise UnsupportedSigma(f"'{tok} of {pattern}' matches no selection")
            results = [self.resolve(n) for n in chosen]
            return any(results) if tok == "1" else all(results)
        if tok in self.names:
            return self.resolve(tok)
        raise UnsupportedSigma(f"unknown token {tok!r} in condition")


def evaluate(rule, event):
    """True if the rule's detection matches the event. Logsource is checked separately."""
    detection = rule["detection"]
    condition = detection["condition"]
    if not isinstance(condition, str):
        raise UnsupportedSigma("list conditions are not supported")
    names = [k for k in detection if k != "condition"]
    cache = {}

    def resolve(name):
        if name not in cache:
            cache[name] = _eval_selection(event, detection[name])
        return cache[name]

    return _Condition(condition, names, resolve).parse()


def logsource_applies(rule, event):
    """True if the event comes from the log source the rule declares."""
    ls = rule["logsource"]
    if ls.get("category") == "proxy":
        return event.get("LogType") == "proxy"
    if ls.get("product") != "windows":
        raise UnsupportedSigma(f"unsupported product {ls.get('product')!r}")
    if ls.get("category") == "process_creation":
        return event.get("Channel", "").startswith("Microsoft-Windows-Sysmon") and event.get("EventID") == "1"
    if ls.get("service") == "security":
        return event.get("Channel") == "Security"
    raise UnsupportedSigma(f"unsupported logsource {ls!r}")


def fires(rule, event):
    return logsource_applies(rule, event) and evaluate(rule, event)
