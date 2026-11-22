"""Prints a per-case PASS/FAIL matrix at the end of the run (alongside pytest's own -v output)."""
_results = []


def pytest_runtest_logreport(report):
    if report.when != "call":
        return
    props = dict(report.user_properties)
    if "case" in props:
        _results.append((props["case"], report.outcome))


def pytest_terminal_summary(terminalreporter):
    if not _results:
        return
    tr = terminalreporter
    tr.section("Detection test matrix: cmdi_sigma.yml")
    tr.write_line(f"{'ID':<6} {'RESULT':<7} {'EXPECTED':<9} {'FORMAT':<22} {'CATEGORY':<22} TECHNIQUE")
    for case, outcome in sorted(_results, key=lambda r: r[0]["id"]):
        result = "PASS" if outcome == "passed" else "FAIL"
        expected = "alert" if case["expected_detected"] else "no alert"
        line = (f"{case['id']:<6} {result:<7} {expected:<9} {case['log_format']:<22} "
                f"{case['category']:<22} {case['technique']}")
        tr.write_line(line, red=(result == "FAIL"), green=(result == "PASS"))
    passed = sum(1 for _, o in _results if o == "passed")
    tr.write_line(f"\n{passed}/{len(_results)} cases PASS")
