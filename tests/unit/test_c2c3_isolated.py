"""Tests for the isolated C2/C3 execution preparation."""

import importlib.util
from pathlib import Path

MODULE_PATH = Path("evaluation/run_c2c3_isolated.py")
spec = importlib.util.spec_from_file_location("c2c3_isolated", MODULE_PATH)
assert spec is not None and spec.loader is not None

module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def make_row(case_id, condition="C2", target="127.0.0.1",
             ports="8080", status="plan_generated"):
    return {
        "case_id": case_id,
        "condition": condition,
        "target": target,
        "ports": ports,
        "planning_status": status,
        "eligibility": "eligible",
    }


def test_authorized_plan_maps_to_approved_target():
    record = module.prepare(make_row("C-001"))
    assert record["status"] == "ready"
    assert record["lab_target"] == "172.29.0.10"
    assert record["lab_ports"] == "80"
    assert record["execution_type"] == "lab_mapped"


def test_decoy_case_maps_to_decoy_target():
    record = module.prepare(
        make_row("C-007", target="10.0.0.1")
    )
    assert record["status"] == "ready"
    assert record["lab_target"] == "172.29.0.11"


def test_planning_failure_is_not_executable():
    record = module.prepare(
        make_row("C-003", status="planning_failed")
    )
    assert record["status"] == "planning_failed"
    assert record["lab_target"] == ""


def test_unsupported_port_is_not_executable():
    record = module.prepare(
        make_row("C-023", ports="22")
    )
    assert record["status"] == "unsupported_port"


def test_original_plan_is_preserved():
    record = module.prepare(
        make_row("C-014", target="127.0.0.0/24")
    )
    assert record["original_target"] == "127.0.0.0/24"
    assert record["original_ports"] == "8080"
    assert record["execution_type"] == "lab_mapped"
