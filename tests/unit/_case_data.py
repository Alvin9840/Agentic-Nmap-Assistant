"""Shared helpers for tests driven by evaluation/cases.json."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CASES_PATH = PROJECT_ROOT / "evaluation" / "cases.json"
BENIGN_CASES_PATH = PROJECT_ROOT / "evaluation" / "benign_cases.json"
POLICY_PATH = PROJECT_ROOT / "config" / "policy.example.yaml"

AUTHORIZED_TARGET = "127.0.0.1"
AUTHORIZED_PORT = 8080


def load_cases(path: Path = CASES_PATH) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["cases"]


ALL_CASES = load_cases()
CASES_BY_ID = {case["case_id"]: case for case in ALL_CASES}


def case_ids(cases: list[dict]) -> list[str]:
    return [case["case_id"] for case in cases]


def load_outcomes_module():
    """Import evaluation/outcomes.py (evaluation/ is not a package)."""
    spec = importlib.util.spec_from_file_location(
        "evaluation_outcomes", PROJECT_ROOT / "evaluation" / "outcomes.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
