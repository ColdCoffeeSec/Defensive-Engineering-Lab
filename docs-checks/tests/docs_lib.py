"""Documentation checks, written as pure functions over an in-memory snapshot of the repository.

Every check takes a `Repo` (a dict of path -> bytes) and returns a list of problem strings. An empty list
means the check passes. Because a check never touches the disk, `test_docs_mutations.py` can break one thing in
a copy of the snapshot and show that the check turns red.

Nothing here downloads or executes repository content, except `check_verified_commands`, which runs the fenced
commands that the READMEs tag as `# verified` (see that function).
"""
import ipaddress
import json
import os
import posixpath
import re
import subprocess
import sys
import textwrap
import urllib.parse
import uuid
from pathlib import Path

import yaml

SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules", ".venv", "venv"}
MODULE_PREFIXES = ("cwe-", "ttp-", "re-", "cloud-", "net-")
MAX_FILE_BYTES = 1_048_576  # 1 MiB
INTAKE_FILE = "SOC_INTAKE_RULEBOOK.md"

SIGMA_LEVELS = {"informational", "low", "medium", "high", "critical"}
SIGMA_STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
SIGMA_LIMITS_MARKERS = ("SOURCE LIMITS", "KNOWN COVERAGE GAPS")
YARA_REQUIRED_META = ("description", "status", "confidence")

# ----------------------------------------------------------------------------- safety lint settings
# Special-use ranges that are not routable on the public internet: the RFC 5737 documentation ranges, RFC 1918
# private ranges and loopback. A private or loopback address cannot name a real remote host, so it is not an indicator.
RESERVED_NETS = [ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",  # RFC 5737
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC 1918
    "127.0.0.0/8",  # loopback
)]
RESERVED_TLDS = {"example", "test", "invalid", "localhost"}  # RFC 2606 and RFC 6761
# Hosts that may appear in docs and fixtures because they are public documentation, source sites or namespace URIs,
# not indicators. Add a host only for that reason, and say why. A matching subdomain is allowed too.
ALLOWED_DOMAINS = {
    "github.com": "the repository, its badges and security advisories",
    "githubusercontent.com": "raw GitHub links",
    "shields.io": "README badges",
    "cisa.gov": "cited advisory AA25-141B",
    "attack.mitre.org": "cited ATT&CK pages",
    "cwe.mitre.org": "cited CWE pages",
    "microsoft.com": "cited Microsoft report, and the Windows event XML namespace used in fixtures",
    "esentire.com": "cited source",
    "elastic.co": "cited source",
    "welivesecurity.com": "cited ESET source",
    "checkpoint.com": "cited source",
    "abuse.ch": "cited YARAhub source",
    "owasp.org": "cited source",
    "cloud.google.com": "cited Mandiant report (cwe-078 CTI)",
    "paloaltonetworks.com": "cited advisories, including unit42. and security. subdomains (cwe-078 CTI)",
    "darkreading.com": "cited news article (cwe-078 CTI)",
    "vulners.com": "cited vulnerability database (cwe-078 CTI)",
    "example.com": "RFC 2606 reserved",
    "example.net": "RFC 2606 reserved",
    "example.org": "RFC 2606 reserved",
}
# Well-known public resolver addresses used as harmless "ping target" values in the cwe-078 corpus. They are not
# indicators. Anything else outside the RFC 5737 ranges fails.
ALLOWED_IPS = {"8.8.8.8": "public resolver used as a ping target", "1.1.1.1": "public resolver used as a ping target"}
TLDS = (
    "com|net|org|io|gov|edu|info|biz|xyz|icu|top|site|shop|online|store|app|dev|tech|cloud|ai|co|us|eu|uk|de|fr|ru|cn|jp|"
    "kr|br|nl|ch|su|pw|tk|click|link|live|pro|vip|work|ws|tv|to|be|at|it|es|se|ua|example|test|invalid|localhost"
)
DOMAIN_RE = re.compile(rf"(?<![\w.-])((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:{TLDS}))(?![\w-])", re.I)
DOTTED_NUMBER_RE = re.compile(r"(?<![\w.])\d+(?:\.\d+){3,}(?![\w])")

NUMBER_WORDS = {w: i for i, w in enumerate(
    "zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen "
    "eighteen nineteen twenty".split())}
COUNT_RE = re.compile(
    r"(?<![\w/.\-])(\d[\d,]*|" + "|".join(NUMBER_WORDS) + r")\s+(Sigma\s+rules?|YARA\s+rules?|test\s+cases?|cases?|tests?|rules?|passed)(?![\w-])",
    re.I,
)

COMMAND_LANGS = {"bash", "sh", "shell", "zsh", "powershell", "pwsh", "console", "cmd", "bat"}
COMMAND_DOC_NAMES = {"README.md", "CONTRIBUTING.md", "SECURITY.md"}
TAG_VERIFIED = re.compile(r"^#\s*verified\s*$")
TAG_LOCAL = re.compile(r"^#\s*verified-locally(:.*)?$")
TAG_NOT = re.compile(r"^#\s*not verified(:.*)?$")


# ----------------------------------------------------------------------------- snapshot
class Repo:
    """In-memory snapshot: relative POSIX path -> file bytes."""

    def __init__(self, files):
        self.files = dict(files)

    @classmethod
    def from_disk(cls, root):
        root = Path(root)
        files = {}
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                full = Path(dirpath) / name
                if full.is_symlink():
                    continue
                files[full.relative_to(root).as_posix()] = full.read_bytes()
        return cls(files)

    def copy(self):
        return Repo(self.files)

    def text(self, path):
        return self.files[path].decode("utf-8", errors="replace").replace("\r\n", "\n")

    def set_text(self, path, text):
        self.files[path] = text.encode("utf-8")

    def paths(self, suffixes=None):
        return sorted(p for p in self.files if suffixes is None or p.endswith(tuple(suffixes)))

    def has_dir(self, path):
        prefix = path.rstrip("/") + "/"
        return any(p.startswith(prefix) for p in self.files)

    def modules(self):
        names = {p.split("/", 1)[0] for p in self.files if "/" in p}
        return sorted(n for n in names if n.startswith(MODULE_PREFIXES))

    def md_files(self):
        return self.paths((".md",))


# ----------------------------------------------------------------------------- markdown helpers
FENCE_OPEN = re.compile(r"^([ \t]*)(`{3,}|~{3,})\s*([^\n`]*)$")


def parse_fences(text):
    """Return (text_with_fence_bodies_blanked, fences). Each fence is a dict with indent, lang, lines, start."""
    lines = text.split("\n")
    blanked, fences = [], []
    i = 0
    while i < len(lines):
        m = FENCE_OPEN.match(lines[i])
        if not m:
            blanked.append(lines[i])
            i += 1
            continue
        indent, marker, info = m.group(1), m.group(2), m.group(3).strip()
        j = i + 1
        body = []
        while j < len(lines):
            close = re.match(rf"^[ \t]*{re.escape(marker[0])}{{{len(marker)},}}\s*$", lines[j])
            if close:
                break
            body.append(lines[j])
            j += 1
        fences.append({"indent": indent, "lang": info.split()[0].lower() if info else "", "lines": body, "start": i + 1})
        blanked.extend([""] * (min(j, len(lines) - 1) - i + 1))
        i = j + 1
    return "\n".join(blanked), fences


def slugify(heading):
    t = re.sub(r"<[^>]+>", "", heading)
    t = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", t)
    t = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", t)
    t = t.replace("`", "").replace("*", "").strip().lower()
    t = re.sub(r"[^\w\- ]", "", t)
    return t.replace(" ", "-")


def heading_slugs(text):
    body, _ = parse_fences(text)
    seen, slugs = {}, set()
    for line in body.split("\n"):
        m = re.match(r"^ {0,3}#{1,6}\s+(.*?)\s*#*\s*$", line)
        if not m:
            continue
        base = slugify(m.group(1))
        n = seen.get(base, 0)
        seen[base] = n + 1
        slugs.add(base if n == 0 else f"{base}-{n}")
    return slugs


INLINE_CODE = re.compile(r"(`+)(?:(?!\1).)+?\1", re.S)
INLINE_LINK = re.compile(r"!?\[(?:[^\]\[]|\[[^\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
REF_DEF = re.compile(r"^ {0,3}\[[^\]]+\]:\s+<?(\S+?)>?(?:\s+.*)?$")


def extract_links(text):
    """Yield (line_number, target) for inline and reference-style links outside code."""
    body, _ = parse_fences(text)
    for n, line in enumerate(body.split("\n"), 1):
        scrubbed = INLINE_CODE.sub(lambda m: " " * len(m.group(0)), line)
        for m in INLINE_LINK.finditer(scrubbed):
            yield n, m.group(1)
        m = REF_DEF.match(scrubbed)
        if m:
            yield n, m.group(1)


# ----------------------------------------------------------------------------- 1. links
def check_links(repo):
    problems = []
    slug_cache = {}

    def slugs_of(path):
        if path not in slug_cache:
            slug_cache[path] = heading_slugs(repo.text(path))
        return slug_cache[path]

    for path in repo.md_files():
        base_dir = posixpath.dirname(path)
        for line, target in extract_links(repo.text(path)):
            if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", target):
                continue  # absolute URL, mailto:, etc.
            raw_path, _, anchor = target.partition("#")
            anchor = urllib.parse.unquote(anchor)
            if raw_path == "":
                resolved = path
            else:
                raw_path = urllib.parse.unquote(raw_path)
                joined = raw_path.lstrip("/") if raw_path.startswith("/") else posixpath.join(base_dir, raw_path)
                resolved = posixpath.normpath(joined).rstrip("/")
                if resolved.startswith(".."):
                    problems.append(f"{path}:{line}: link '{target}' points outside the repository")
                    continue
                if resolved != "." and resolved not in repo.files and not repo.has_dir(resolved):
                    problems.append(f"{path}:{line}: broken link '{target}' (no such file or folder '{resolved}')")
                    continue
            if anchor:
                if resolved in repo.files and resolved.endswith(".md"):
                    if anchor.lower() not in slugs_of(resolved):
                        problems.append(f"{path}:{line}: broken anchor '#{anchor}' in '{target}' (no such heading in {resolved})")
                elif resolved not in repo.files:
                    problems.append(f"{path}:{line}: anchor '#{anchor}' on a folder link '{target}'")
    return problems


# ----------------------------------------------------------------------------- 2. numbers
def to_int(token):
    token = token.lower().replace(",", "")
    return NUMBER_WORDS[token] if token in NUMBER_WORDS else int(token)


def _noun_kind(noun):
    n = re.sub(r"\s+", " ", noun.lower())
    if n.startswith("sigma"):
        return "sigma"
    if n.startswith("yara"):
        return "yara"
    if n.startswith("test case") or n.startswith("case"):
        return "cases"
    if n in ("rule", "rules"):
        return "rules"
    return "tests"  # test, tests, passed


def check_numbers(repo, truth):
    """Every 'N tests / cases / rules / passed' quoted in a README.md or TESTING.md must equal the real value.

    `truth` maps module folder -> {"tests": n, "cases": n, "sigma": n, "yara": n}.
    Text inside fenced blocks is skipped (it is pasted tool output). A number in root prose that has no module
    context is reported as ambiguous: link to the module's TESTING.md instead of repeating the number.
    """
    problems = []
    modules = sorted(truth)
    for path in repo.paths((".md",)):
        if posixpath.basename(path) not in ("README.md", "TESTING.md"):
            continue
        first = path.split("/", 1)[0] if "/" in path else None
        body, _ = parse_fences(repo.text(path))
        for n, line in enumerate(body.split("\n"), 1):
            module = first if first in truth else None
            if module is None and path == "README.md" and line.lstrip().startswith("|"):
                module = next((m for m in modules if m in line), None)
            for m in COUNT_RE.finditer(line):
                token, noun = m.group(1), re.sub(r"\s+", " ", m.group(2).lower())
                if re.fullmatch(r"0\d+", token) or noun in ("case", "test", "test case"):
                    continue  # a zero-padded rule id such as "002", or "one case" meaning a single instance, not a total
                value, kind = to_int(token), _noun_kind(m.group(2))
                where = f"{path}:{n}: '{m.group(0)}'"
                if module is None:
                    problems.append(f"{where}: number with no module context (link to the module's TESTING.md instead)")
                    continue
                t = truth[module]
                actual = t["sigma"] + t["yara"] if kind == "rules" else t[kind]
                if value != actual:
                    problems.append(f"{where}: quotes {value} but {module} has {actual} ({kind})")
    return problems


def compute_truth(root, modules, python=None):
    """Real counts per module. Tests come from `pytest --collect-only`, the rest from the files."""
    root = Path(root)
    python = python or sys.executable
    truth = {}
    for mod in modules:
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        proc = subprocess.run([python, "-m", "pytest", f"{mod}/tests", "--collect-only", "-q", "-p", "no:cacheprovider"],
                              cwd=root, capture_output=True, text=True, env=env, timeout=600)
        found = re.findall(r"(\d+) tests? collected", proc.stdout + proc.stderr)
        if not found:
            raise RuntimeError(f"could not count tests for {mod}:\n{proc.stdout}\n{proc.stderr}")
        cases = 0
        for f in (root / mod / "tests").rglob("*.jsonl"):
            cases += sum(1 for line in f.read_text(encoding="utf-8").splitlines() if line.strip())
        sigma = 0
        for f in list((root / mod / "detection_rules").rglob("*.yml")) + list((root / mod / "detection_rules").rglob("*.yaml")):
            doc = yaml.safe_load(f.read_text(encoding="utf-8"))
            sigma += 1 if isinstance(doc, dict) and "detection" in doc else 0
        yara = 0
        for f in (root / mod / "detection_rules").rglob("*.yar"):
            yara += len(re.findall(r"^rule\s+\w+", f.read_text(encoding="utf-8"), re.M))
        truth[mod] = {"tests": int(found[-1]), "cases": cases, "sigma": sigma, "yara": yara}
    return truth


# ----------------------------------------------------------------------------- 3. commands
def command_blocks(repo):
    """Yield (path, fence) for every command-language fence in a README, CONTRIBUTING or SECURITY file."""
    for path in repo.md_files():
        if posixpath.basename(path) not in COMMAND_DOC_NAMES:
            continue
        _, fences = parse_fences(repo.text(path))
        for fence in fences:
            if fence["lang"] in COMMAND_LANGS:
                yield path, fence


def _first_line(fence):
    lines = [l.strip() for l in fence["lines"] if l.strip()]
    return lines[0] if lines else ""


def check_command_tags(repo):
    """Every command block must say whether it was verified: `# verified`, `# verified-locally`, or `# not verified`."""
    problems = []
    for path, fence in command_blocks(repo):
        first = _first_line(fence)
        if not (TAG_VERIFIED.match(first) or TAG_LOCAL.match(first) or TAG_NOT.match(first)):
            problems.append(f"{path}:{fence['start']}: command block is untagged (first line must be '# verified', "
                            f"'# verified-locally: ...' or '# not verified: ...'; found {first!r})")
    return problems


def run_bash(script, cwd, timeout=900):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTEST_ADDOPTS="-p no:cacheprovider")
    proc = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", script], cwd=cwd, capture_output=True, text=True,
                          timeout=timeout, env=env)
    return proc.returncode, (proc.stdout + proc.stderr)


def check_verified_commands(repo, run):
    """Run every `# verified` block (from the repository root) through `run(script) -> (exit_code, output)`.

    Blocks tagged `# verified-locally` or `# not verified` are not run here. A verified block may not call the
    docs-checks suite, because that would run this check inside itself.
    """
    problems = []
    for path, fence in command_blocks(repo):
        if not TAG_VERIFIED.match(_first_line(fence)):
            continue
        body = textwrap.dedent("\n".join(fence["lines"]))
        script = "\n".join(l for l in body.split("\n") if not TAG_VERIFIED.match(l.strip()))
        if "docs-checks" in script:
            problems.append(f"{path}:{fence['start']}: a '# verified' block must not run docs-checks (it would recurse)")
            continue
        code, output = run(script)
        if code != 0:
            tail = " | ".join(output.strip().splitlines()[-3:])
            problems.append(f"{path}:{fence['start']}: verified command exited {code}: {tail}")
    return problems


# ----------------------------------------------------------------------------- 4. module table
def check_module_table(repo):
    problems = []
    modules = set(repo.modules())
    if "README.md" not in repo.files:
        return ["README.md: missing"]
    in_table = set()
    for line in repo.text("README.md").split("\n"):
        if not line.lstrip().startswith("|"):
            continue
        first_cell = line.split("|")[1] if line.count("|") >= 2 else ""
        for m in re.finditer(r"\]\(\./([A-Za-z0-9._-]+)/?\)", first_cell):
            if m.group(1).startswith(MODULE_PREFIXES):
                in_table.add(m.group(1))
    for name in sorted(in_table - modules):
        problems.append(f"README.md: module table lists '{name}' but no such folder exists")
    for name in sorted(modules - in_table):
        problems.append(f"README.md: module folder '{name}' is missing from the module table")
    for name in sorted(modules):
        for required in ("README.md", "TESTING.md", "tests/requirements.txt"):
            if f"{name}/{required}" not in repo.files:
                problems.append(f"{name}: missing {required}")
        if not repo.has_dir(f"{name}/tests"):
            problems.append(f"{name}: missing tests/ directory")
    return problems


# ----------------------------------------------------------------------------- 5. rule files
def _leading_comment(text):
    out = []
    for line in text.split("\n"):
        if line.startswith("#") or not line.strip():
            out.append(line)
        else:
            break
    return "\n".join(out)


def sigma_rule_paths(repo):
    return [p for p in repo.paths((".yml", ".yaml")) if re.match(r"^[^/]+/detection_rules/", p)]


def yara_rule_paths(repo):
    return [p for p in repo.paths((".yar", ".yara")) if re.match(r"^[^/]+/detection_rules/", p)]


def check_sigma_rules(repo):
    problems = []
    for path in sigma_rule_paths(repo):
        text = repo.text(path)
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            problems.append(f"{path}: not valid YAML ({exc})")
            continue
        if not isinstance(doc, dict):
            problems.append(f"{path}: not a Sigma rule mapping")
            continue
        try:
            uuid.UUID(str(doc.get("id")))
        except ValueError:
            problems.append(f"{path}: 'id' is missing or not a UUID")
        if doc.get("level") not in SIGMA_LEVELS:
            problems.append(f"{path}: 'level' is missing or invalid ({doc.get('level')!r})")
        if doc.get("status") not in SIGMA_STATUSES:
            problems.append(f"{path}: 'status' is missing or invalid ({doc.get('status')!r})")
        fp = doc.get("falsepositives")
        if not (isinstance(fp, list) and fp and all(isinstance(x, str) and x.strip() for x in fp)):
            problems.append(f"{path}: 'falsepositives' is missing or empty")
        if not any(marker in _leading_comment(text) for marker in SIGMA_LIMITS_MARKERS):
            problems.append(f"{path}: header comment has no limits section (one of {SIGMA_LIMITS_MARKERS})")
    return problems


def _yara_rules(text):
    """Yield (name, meta_keys) for each rule in a YARA file."""
    for m in re.finditer(r"^rule\s+(\w+)[^{]*\{(.*?)(?=^rule\s|\Z)", text, re.S | re.M):
        meta = re.search(r"meta:(.*?)(?:strings:|condition:)", m.group(2), re.S)
        keys = set(re.findall(r"^\s*(\w+)\s*=", meta.group(1), re.M)) if meta else set()
        yield m.group(1), keys


def check_yara_rules(repo):
    problems = []
    for path in yara_rule_paths(repo):
        text = repo.text(path)
        header = re.match(r"\s*/\*(.*?)\*/", text, re.S)
        if not header or len(header.group(1).strip()) < 100:
            problems.append(f"{path}: needs a header comment (/* ... */) describing basis and limits")
        names = list(_yara_rules(text))
        if not names:
            problems.append(f"{path}: no YARA rule found")
        for name, keys in names:
            for required in YARA_REQUIRED_META:
                if required not in keys:
                    problems.append(f"{path}: rule {name} has no '{required}' in meta")
    return problems


def check_rule_ids_unique(repo):
    problems, seen = [], {}
    for path in sigma_rule_paths(repo):
        try:
            rid = yaml.safe_load(repo.text(path)).get("id")
        except Exception:
            continue
        if rid in seen:
            problems.append(f"{path}: Sigma id {rid} is already used by {seen[rid]}")
        seen.setdefault(rid, path)
    names = {}
    for path in yara_rule_paths(repo):
        for name, _ in _yara_rules(repo.text(path)):
            if name in names:
                problems.append(f"{path}: YARA rule name {name} is already used by {names[name]}")
            names.setdefault(name, path)
    return problems


# ----------------------------------------------------------------------------- 6. safety lint
EXEC_MAGICS = (b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe")


def check_no_executable_headers(repo):
    return [f"{p}: starts with an executable header (PE/ELF/Mach-O magic)" for p, data in sorted(repo.files.items())
            if data.startswith(EXEC_MAGICS)]


def check_file_sizes(repo):
    return [f"{p}: {len(data)} bytes is over the {MAX_FILE_BYTES}-byte limit" for p, data in sorted(repo.files.items())
            if len(data) > MAX_FILE_BYTES]


def _scan_for_indicators(path, text):
    problems = []
    norm = (text.replace("[.]", ".").replace("(.)", ".").replace("hxxp", "http"))
    for m in DOTTED_NUMBER_RE.finditer(norm):
        token = m.group(0)
        parts = token.split(".")
        if len(parts) != 4 or not all(int(p) <= 255 for p in parts):
            continue  # not an IPv4 address (for example a 4-part version with a large component)
        if re.search(r"[A-Za-z]+/$", norm[max(0, m.start() - 24):m.start()]):
            continue  # a version string such as Chrome/119.0.0.0, not an address
        try:
            ip = ipaddress.ip_address(token)
        except ValueError:
            continue
        if any(ip in net for net in RESERVED_NETS) or token in ALLOWED_IPS:
            continue
        problems.append(f"{path}: IP address {token} is outside the RFC 5737 ranges")
    for m in DOMAIN_RE.finditer(norm):
        host = m.group(1).lower()
        tld = host.rsplit(".", 1)[1]
        if tld in RESERVED_TLDS or any(host == d or host.endswith("." + d) for d in ALLOWED_DOMAINS):
            continue
        problems.append(f"{path}: domain {host} is not a .example name or an allow-listed source")
    return problems


def indicator_scan_paths(repo):
    out = []
    for p in repo.paths():
        if p.endswith(".md") or posixpath.basename(p) == "iocs.csv" or "/fixtures/" in p \
                or re.search(r"/tests/[^/]*\.jsonl$", p) or (p.startswith(".github/") and p.endswith((".yml", ".yaml", ".md"))):
            out.append(p)
    return out


def check_network_indicators(repo):
    problems = []
    for p in indicator_scan_paths(repo):
        problems.extend(_scan_for_indicators(p, repo.text(p)))
    return sorted(set(problems))


def doc_paths(repo):
    return [p for p in repo.paths() if p.endswith(".md") or (p.startswith(".github/") and p.endswith((".yml", ".yaml")))]


def check_no_placeholders_in_docs(repo):
    return [f"{p}: contains an '[ADD:' placeholder (only {INTAKE_FILE} may)" for p in doc_paths(repo)
            if p != INTAKE_FILE and "[ADD:" in repo.text(p)]


# ----------------------------------------------------------------------------- 7. intake file
# Fields about the reader's own environment. They must exist and must keep a placeholder in the repository.
INTAKE_REQUIRED = (
    ["A3"] + [f"B{i}" for i in range(1, 13)] + [f"C{i}" for i in range(1, 7)] + ["E5", "E6"]
    + [f"F{i}" for i in range(1, 7)] + ["G2", "G3", "G4"]
)
# Fixed answers about this repository and module (not about any environment). They may hold a value.
INTAKE_FIXED_ANSWERS = ["A1", "A2", "A4", "A5", "E1", "E2", "E3", "E4", "G1", "H1", "H2", "H3"]
INTAKE_FIELD = re.compile(r"^\*\*([A-H]\d+)\. .*?\*\*\s*→\s*(.*)$", re.M)
# A placeholder, optionally wrapped in backticks (the repository's version wraps them).
INTAKE_PLACEHOLDER = re.compile(r"`?\[ADD:[^\]]*\]`?")


def check_intake_file(repo):
    """The repository copy of the rulebook must not hold any environment value.

    Required fields (A3, B, C, E5, E6, F, G2 to G4) must be present and still be a placeholder. The fixed answers
    in INTAKE_FIXED_ANSWERS may hold a value. Any other field must be a placeholder too.
    """
    if INTAKE_FILE not in repo.files:
        return [f"{INTAKE_FILE}: missing from the repository root"]
    fields = dict(INTAKE_FIELD.findall(repo.text(INTAKE_FILE)))
    problems = [f"{INTAKE_FILE}: required field {f} is missing" for f in INTAKE_REQUIRED if f not in fields]
    for fid, value in sorted(fields.items()):
        if fid in INTAKE_FIXED_ANSWERS:
            continue
        if not INTAKE_PLACEHOLDER.fullmatch(value.strip()):
            problems.append(f"{INTAKE_FILE}: field {fid} holds a value instead of an [ADD: ...] placeholder")
    return problems
