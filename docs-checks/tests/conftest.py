"""Shared fixtures for the documentation checks."""
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parents[1]  # repository root: docs-checks/tests/conftest.py -> docs-checks -> repo
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from docs_lib import Repo, compute_truth  # noqa: E402


@pytest.fixture(scope="session")
def repo_root():
    return ROOT


@pytest.fixture(scope="session")
def repo(repo_root):
    """Snapshot of the repository on disk. Tests copy it before changing anything."""
    return Repo.from_disk(repo_root)


@pytest.fixture(scope="session")
def truth(repo_root, repo):
    """Real test, case and rule counts per suite (modules and docs-* folders), from pytest collection and the files."""
    return compute_truth(repo_root, repo.suites())
