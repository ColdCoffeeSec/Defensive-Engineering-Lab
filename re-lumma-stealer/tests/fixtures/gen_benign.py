"""Seeded generator for a SYNTHETIC benign event corpus.

The corpus is built at test time from a fixed seed, so it is identical on every run and nothing is
stored. Counts are asserted in test_sigma_rules.py.

This is NOT a measure of real-world false positives. Every value is invented, and the templates are the
author's guess at ordinary activity. The real benign baseline comes from the deployer's own endpoints,
run locally and never committed (TESTING.md, "Baseline and real-data log").
"""
import base64
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from logparse import build_proxy  # noqa: E402
from winevent import build_security4663, build_sysmon1  # noqa: E402

SEED = 1337
RULE001_COUNT = 300
RULE002_COUNT = 200
RULE003_COUNT = 200

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
PWSH = r"C:\Program Files\PowerShell\7\pwsh.exe"
EXPLORER = r"C:\Windows\explorer.exe"
SCRIPT_NAMES = ["inventory", "backup-check", "cleanup", "report", "sync-users", "patch-status"]
INTRANET = ["intranet.example", "wiki.example", "tools.lab.example"]


def _b64(rng):
    text = f"Write-Output 'job {rng.randint(1, 99999)}'"
    return base64.b64encode(text.encode("utf-16-le")).decode()


def _rule001_templates(rng):
    """Each returns (parent, image, command_line). None of these may match rule 001."""
    script = rng.choice(SCRIPT_NAMES)
    host = rng.choice(INTRANET)
    n = rng.randint(1, 500)
    return [
        # explorer starts ordinary programs
        (EXPLORER, r"C:\Windows\System32\notepad.exe", rf"notepad.exe C:\Users\user{n:02d}\notes{n}.txt"),
        (EXPLORER, r"C:\Windows\System32\cmd.exe", "cmd /c dir"),
        (EXPLORER, r"C:\Program Files\Google\Chrome\Application\chrome.exe", f"chrome.exe https://{host}/page{n}"),
        (EXPLORER, r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", f"msedge.exe https://{host}/"),
        (EXPLORER, r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", rf"WINWORD.EXE C:\Users\user{n:02d}\doc{n}.docx"),
        # explorer starts PowerShell on scripts and plain commands
        (EXPLORER, PS, rf"powershell -ExecutionPolicy Bypass -File C:\Tools\{script}.ps1"),
        (EXPLORER, PS, f'powershell -NoProfile -Command "Get-Service | Where-Object Status -eq Running"'),
        (EXPLORER, PWSH, rf"pwsh -File C:\Tools\{script}.ps1 -Verbose"),
        (EXPLORER, PS, f'powershell -c "Start-Process iexplore https://{host}/help"'),
        (EXPLORER, PS, f"powershell -NoProfile -c \"Write-Host 'see https://{host}/status'\""),
        (EXPLORER, r"C:\Windows\System32\mshta.exe", rf'mshta "C:\Program Files\Legacy\app{n}.hta"'),
        # encoded or cradle commands from non-explorer parents: scheduled jobs, agents, terminals
        (r"C:\Windows\System32\svchost.exe", PS, f"powershell -NoProfile -enc {_b64(rng)}"),
        (r"C:\Windows\CCM\CcmExec.exe", PS, f"powershell -ExecutionPolicy Bypass -EncodedCommand {_b64(rng)}"),
        (r"C:\Program Files\Microsoft VS Code\Code.exe", PS, f'powershell -c "iex (irm https://{host}/tool.ps1)"'),
        (r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal\WindowsTerminal.exe", PWSH, f"pwsh -ec {_b64(rng)}"),
        (r"C:\Program Files\Legacy\launcher.exe", r"C:\Windows\System32\mshta.exe", f"mshta https://{host}/app.hta"),
    ]


def rule001_events():
    rng = random.Random(SEED)
    events = []
    for _ in range(RULE001_COUNT):
        parent, image, cmd = rng.choice(_rule001_templates(rng))
        events.append(build_sysmon1(ParentImage=parent, Image=image, CommandLine=cmd,
                                    ProcessId=str(rng.randint(1000, 60000)), User=f"LAB\\user{rng.randint(1, 50):02d}"))
    return events


def rule002_events():
    rng = random.Random(SEED + 1)
    store_files = ["Login Data", "Network\\Cookies", "Web Data", "Local State"]
    events = []
    for _ in range(RULE002_COUNT):
        user = f"user{rng.randint(1, 50):02d}"
        base = rf"C:\Users\{user}\AppData\Local"
        kind = rng.randint(0, 5)
        if kind == 0:  # Chrome reads its store
            proc, obj = r"C:\Program Files\Google\Chrome\Application\chrome.exe", rf"{base}\Google\Chrome\User Data\Default\{rng.choice(store_files)}"
        elif kind == 1:  # Edge reads its store
            proc, obj = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", rf"{base}\Microsoft\Edge\User Data\Default\{rng.choice(store_files)}"
        elif kind == 2:  # Firefox reads its store
            proc = r"C:\Program Files\Mozilla Firefox\firefox.exe"
            obj = rf"C:\Users\{user}\AppData\Roaming\Mozilla\Firefox\Profiles\x{rng.randint(1000, 9999)}.default\{rng.choice(['logins.json', 'key4.db', 'cookies.sqlite'])}"
        elif kind == 3:  # updaters read Local State
            proc = rng.choice([r"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe", r"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe"])
            obj = rf"{base}\Google\Chrome\User Data\Local State"
        elif kind == 4:  # any process reads a non-store file in a profile
            proc = rng.choice([r"C:\Program Files\Vendor Sync\sync.exe", r"C:\Windows\System32\svchost.exe", r"C:\Program Files\Vendor PM\pm.exe"])
            obj = rf"{base}\Google\Chrome\User Data\Default\{rng.choice(['Preferences', 'History', 'Bookmarks', 'Favicons'])}"
        else:  # a non-browser reads a store-named file outside any profile folder
            proc = rng.choice([r"C:\Program Files\Vendor Sync\sync.exe", r"C:\Program Files\Vendor PM\pm.exe"])
            obj = rf"C:\ProgramData\Vendor\{rng.choice(['Login Data', 'Cookies', 'logins.json'])}"
        events.append(build_security4663(ObjectName=obj, ProcessName=proc, SubjectUserName=user))
    return events


def rule003_events():
    """Benign proxy records. No record carries either of the two ESET User-Agent strings."""
    rng = random.Random(SEED + 2)
    uas = [f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36"
           for v in list(range(120, 146))]
    uas += [f"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{v}.0) Gecko/20100101 Firefox/{v}.0" for v in (128, 130, 133, 140)]
    uas += [f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36 Edg/{v}.0.0.0"
            for v in (125, 130, 136)]
    uas += ["python-requests/2.32.3", "curl/8.9.1", "Microsoft-CryptoAPI/10.0", "Windows-Update-Agent/10.0.10011.16384"]
    hosts = ["app.example", "www.example", "intranet.example", "updates.example"]
    events = []
    for _ in range(RULE003_COUNT):
        events.append(build_proxy(**{
            "cs-method": rng.choice(["GET", "GET", "POST", "HEAD"]), "c-useragent": rng.choice(uas),
            "cs-host": rng.choice(hosts), "cs-uri-stem": f"/p{rng.randint(1, 999)}", "c-ip": f"192.0.2.{rng.randint(2, 250)}"}))
    return events
