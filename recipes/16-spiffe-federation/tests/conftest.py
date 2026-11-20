"""Offline unit tests: no network, no Docker, no DNSid Local, no dnsid CLI.

`src/` is put on the import path by `[tool.pytest.ini_options] pythonpath` in pyproject.toml.
"""
import sys
from pathlib import Path

HERE = str(Path(__file__).resolve().parent)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import pytest  # noqa: E402

import helpers as H  # noqa: E402


@pytest.fixture
def env(tmp_path):
    return H.Env(tmp_path)


@pytest.fixture
def policy():
    return H.make_policy()
