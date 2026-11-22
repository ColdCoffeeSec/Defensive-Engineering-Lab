"""Shared paths and import setup for the re-lumma-stealer tests."""
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
for extra in (TESTS, TESTS / "fixtures", ROOT / "tools"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

SIGMA_DIR = ROOT / "detection_rules" / "sigma"
YARA_DIR = ROOT / "detection_rules" / "yara"
LOG_DIR = TESTS / "fixtures" / "logs"
REQUIREMENTS = TESTS / "requirements.txt"
