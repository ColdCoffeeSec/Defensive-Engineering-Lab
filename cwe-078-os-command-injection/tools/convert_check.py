"""Convert this module's Sigma rules with pySigma for Splunk and Microsoft 365 Defender. Fails on any conversion error.

What this checks: that pySigma can turn each rule into a query for each backend without raising an error, and that
each conversion returns at least one query.

What this does NOT check:
  * No processing pipeline and no field mapping is applied. Neither backend ships a pipeline for the `webserver`
    log source (see TESTING.md), and none is invented here. The rule's field names (cs-uri-stem, cs-uri-query, c-ip, ...)
    therefore pass through unmapped.
  * The converted query is NOT run against Splunk or Microsoft 365 Defender, so it is not known to be valid there.

Install tests/requirements-conversion.txt in its own environment first.

Usage: python tools/convert_check.py [--rules PATH]   (PATH is a rule file or a folder; default: ../detection_rules)
Exit code: 0 if every rule converted for every backend, 1 otherwise.
"""
import argparse
import importlib.metadata as md
import re
import sys
from pathlib import Path

from sigma.collection import SigmaCollection

PACKAGES = ("pysigma", "pysigma-backend-splunk", "pysigma-backend-kusto", "pysigma-backend-microsoft365defender")


def load_backends():
    """(target name, class) for each backend. The microsoft365defender target resolves to the Kusto backend."""
    from sigma.backends.microsoft365defender import backends as m365_backends
    from sigma.backends.splunk import SplunkBackend

    return [("splunk", SplunkBackend), ("microsoft365defender", m365_backends["microsoft365defender"])]


def rule_files(path):
    path = Path(path)
    return [path] if path.is_file() else sorted(list(path.rglob("*.yml")) + list(path.rglob("*.yaml")))


def convert(backend_cls, text):
    """Convert one rule file with NO processing pipeline. Raises on any problem."""
    collection = SigmaCollection.from_yaml(text)
    problems = [str(e) for rule in collection.rules for e in rule.errors]
    if problems:
        raise ValueError("rule has errors: " + "; ".join(problems))
    queries = backend_cls().convert(collection)
    if not queries:
        raise ValueError("conversion returned no query")
    return queries


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--rules", default=str(Path(__file__).resolve().parents[1] / "detection_rules"))
    args = ap.parse_args(argv)

    for pkg in PACKAGES:
        try:
            print(f"{pkg} {md.version(pkg)}")
        except md.PackageNotFoundError:
            print(f"{pkg} NOT INSTALLED")
    files = rule_files(args.rules)
    if not files:
        print(f"ERROR: no rule files under {args.rules}")
        return 1
    failures = 0
    for target, cls in load_backends():
        print(f"\n== target {target} ({cls.__module__}.{cls.__name__}), no processing pipeline")
        for f in files:
            try:
                queries = convert(cls, f.read_text(encoding="utf-8"))
                shown = re.sub(r"\s+", " ", str(queries[0]))[:300]
                print(f"OK    {f.name}: {len(queries)} query | {shown}...")
            except Exception as exc:  # any error is a failed conversion
                failures += 1
                print(f"ERROR {f.name}: {type(exc).__name__}: {str(exc)[:400]}")
    print("\nNOTE: converted without a pipeline or field mapping; the output was not run against a SIEM.")
    print(f"RESULT: {'FAILED' if failures else 'OK'} ({failures} conversion error(s))")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
