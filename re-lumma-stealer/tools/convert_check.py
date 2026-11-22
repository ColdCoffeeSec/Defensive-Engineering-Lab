"""Convert this module's Sigma rules with pySigma for Splunk and Microsoft 365 Defender (Kusto). Fails on any conversion error.

Same design as cwe-078-os-command-injection/tools/convert_check.py, with one addition: a pipeline is applied only
where an installed package ships one for the rule's log source (PIPELINES below). No field mapping is invented here.

What this checks: that pySigma can turn each rule into a query for each backend without raising an error, and that
each conversion returns a non-empty query. YARA rules are not converted.

What this does NOT check:
  * The converted queries are NOT run against Splunk or Microsoft 365 Defender, so they are not known to be valid there.
  * Splunk: `splunk_windows` is applied to the Windows rules (001, 002) and `splunk_cim` to the proxy rule (003), because
    those are the pipelines the package ships for those log sources. See TESTING.md for what each one changed.
  * Microsoft 365 Defender: the Kusto package ships pipeline modules, but under the pinned pySigma every one of them fails
    to import (see requirements-conversion.txt). No pipeline is applied, so the Kusto output has no table name and keeps
    the rule's own field names. It converts; it is not a ready-to-run query.
  * Rule 002 needs Security event 4663 with a SACL on browser profile paths. A converted query does not change that.

Install tests/requirements-conversion.txt in its own environment first.

Usage: python tools/convert_check.py [--rules PATH]   (PATH is a rule file or a folder; default: ../detection_rules/sigma)
Exit code: 0 if every rule converted for every backend, 1 otherwise.
"""
import argparse
import importlib
import importlib.metadata as md
import re
import sys
from pathlib import Path

from sigma.collection import SigmaCollection

PACKAGES = ("pysigma", "pysigma-backend-splunk", "pysigma-backend-kusto", "pysigma-backend-microsoft365defender")
KUSTO_PIPELINE_MODULES = (
    "sigma.pipelines.microsoftxdr",
    "sigma.pipelines.microsoft365defender",
    "sigma.pipelines.azuremonitor",
    "sigma.pipelines.sentinelasim",
)


def load_backends():
    """(target name, class) for each backend. The microsoft365defender target resolves to the Kusto backend."""
    from sigma.backends.microsoft365defender import backends as m365_backends
    from sigma.backends.splunk import SplunkBackend

    return [("splunk", SplunkBackend), ("microsoft365defender", m365_backends["microsoft365defender"])]


def splunk_pipeline(logsource):
    """The Splunk pipeline the package ships for this log source, as (name, pipeline), or None.

    splunk_windows covers Windows log sources. splunk_cim is the only shipped Splunk pipeline with a proxy field mapping.
    """
    from sigma.pipelines import splunk

    if logsource.product == "windows":
        return "splunk_windows", splunk.splunk_windows_pipeline()
    if logsource.category == "proxy":
        return "splunk_cim", splunk.splunk_cim_data_model()
    return None


def pipeline_for(target, logsource):
    """(name, ProcessingPipeline) or None. Kusto has none: its pipeline modules do not import under the pinned pySigma."""
    return splunk_pipeline(logsource) if target == "splunk" else None


def rule_files(path):
    path = Path(path)
    return [path] if path.is_file() else sorted(list(path.rglob("*.yml")) + list(path.rglob("*.yaml")))


def convert(backend_cls, text, target):
    """Convert one rule file. Returns (queries, pipeline name or None, queries without a pipeline). Raises on any problem."""
    collection = SigmaCollection.from_yaml(text)
    problems = [str(e) for rule in collection.rules for e in rule.errors]
    if problems:
        raise ValueError("rule has errors: " + "; ".join(problems))
    chosen = pipeline_for(target, collection.rules[0].logsource)
    bare = [str(q) for q in backend_cls().convert(collection)]
    if chosen is None:
        queries = bare
    else:
        queries = [str(q) for q in backend_cls(processing_pipeline=chosen[1]).convert(collection)]
    if not queries or not all(q.strip() for q in queries):
        raise ValueError("conversion returned no query")
    return queries, (chosen[0] if chosen else None), bare


def report_kusto_pipeline_modules():
    """Print whether the Kusto package's pipeline modules import. Information only; nothing here is applied."""
    for module in KUSTO_PIPELINE_MODULES:
        try:
            importlib.import_module(module)
            print(f"  pipeline module {module}: imports")
        except Exception as exc:  # reported, not fatal: no Kusto pipeline is applied either way
            print(f"  pipeline module {module}: IMPORT FAILS ({type(exc).__name__}: {str(exc)[:110]})")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--rules", default=str(Path(__file__).resolve().parents[1] / "detection_rules" / "sigma"))
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
        print(f"\n== target {target} ({cls.__module__}.{cls.__name__})")
        if target == "microsoft365defender":
            report_kusto_pipeline_modules()
        for f in files:
            try:
                queries, pipeline, bare = convert(cls, f.read_text(encoding="utf-8"), target)
                if pipeline is None:
                    note = "pipeline: none"
                else:
                    note = f"pipeline: {pipeline} ({'output identical to no pipeline' if queries == bare else 'output differs from no pipeline'})"
                shown = re.sub(r"\s+", " ", queries[0])[:300]
                print(f"OK    {f.name}: {len(queries)} query, {note} | {shown}...")
            except Exception as exc:  # any error is a failed conversion
                failures += 1
                print(f"ERROR {f.name}: {type(exc).__name__}: {str(exc)[:400]}")
    print("\nNOTE: the output was not run against a SIEM. Kusto output has no pipeline, so no table and no field mapping.")
    print(f"RESULT: {'FAILED' if failures else 'OK'} ({failures} conversion error(s))")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
