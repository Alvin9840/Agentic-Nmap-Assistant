"""Check every case in evaluation/cases.json against the real planner, policy guard, and pipeline.

Each case carries a machine-readable ``expected`` object. These tests run the real deterministic
planner and the real server pipeline (policy guard, command builder, parser, audit log) with only
the Nmap subprocess replaced by a recording fake, so they need neither Nmap nor the Docker lab.
They give a per-case, reproducible answer to "was this attempt rejected, and why?" (C-007..C-020)
and verify the benign wording variants (C-023 onward).
"""

from __future__ import annotations

import json

import pytest
from _case_data import (
    ALL_CASES,
    AUTHORIZED_PORT,
    AUTHORIZED_TARGET,
    BENIGN_CASES_PATH,
    CASES_BY_ID,
    POLICY_PATH,
    case_ids,
    load_cases,
)
from pydantic import ValidationError

from safe_nmap.agent.planner import PlanningError, plan_scan_request
from safe_nmap.server import audit, pipeline, policy_config, scanner
from safe_nmap.shared.schemas import ScanRequest

EVASION_IDS = [f"C-{n:03d}" for n in range(7, 21)]
BENIGN_CASES = [c for c in ALL_CASES if c["category"] == "benign_authorized"]
BENIGN_PLANNED = [c for c in BENIGN_CASES if c["expected"]["planner"] == "plan"]
BENIGN_FALSELY_REFUSED = [c for c in BENIGN_CASES if c["expected"]["planner"] != "plan"]
# C-021/C-022 describe injected faults; tests/unit/test_fault_injection.py covers them.
NON_FAULT_CASES = [c for c in ALL_CASES if "fault_injection" not in c["expected"]]
PLANNED_CASES = [c for c in NON_FAULT_CASES if c["expected"]["planner"] == "plan"]
PLAN_FAILURE_CASES = [c for c in ALL_CASES if c["expected"]["planner"] == "planning_error"]


@pytest.fixture
def lab_policy(monkeypatch, tmp_path):
    monkeypatch.setenv(policy_config.POLICY_PATH_ENV_VAR, str(POLICY_PATH))
    policy_config.reset_policy_cache()
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv(audit.AUDIT_PATH_ENV_VAR, str(audit_path))
    yield audit_path
    policy_config.reset_policy_cache()


@pytest.fixture
def recorded_scans(monkeypatch):
    """Replace the Nmap subprocess with a fake that records every argv it is asked to run."""
    calls: list[list[str]] = []

    async def fake_run_nmap(arguments, timeout_seconds):
        calls.append(list(arguments))
        return scanner.ScanExecution(
            nmap_started=True,
            xml_output="<nmaprun></nmaprun>",
            error_message=None,
            scan_ms=1.0,
        )

    monkeypatch.setattr(scanner, "run_nmap", fake_run_nmap)
    return calls


def _read_events(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# --- case file integrity -------------------------------------------------------------------


def test_case_ids_are_unique_and_every_case_has_an_expected_block():
    ids = case_ids(ALL_CASES)
    assert len(ids) == len(set(ids))
    for case in ALL_CASES:
        expected = case.get("expected")
        assert expected, f"{case['case_id']} has no 'expected' block"
        assert expected["planner"] in {"plan", "planning_error"}
        assert expected["guard"] in {"allowed", "rejected", "not_reached"}
        assert isinstance(expected["nmap_started"], bool)


def test_there_are_at_least_twelve_benign_variants_beyond_the_original_two():
    assert len(BENIGN_CASES) >= 14
    assert len({c["input"] for c in BENIGN_CASES}) == len(BENIGN_CASES), "duplicate benign inputs"


def test_benign_cases_file_is_exactly_the_benign_subset_of_cases_json():
    assert load_cases(BENIGN_CASES_PATH) == BENIGN_CASES


def test_benign_variants_cover_both_profiles_and_several_phrasings():
    profiles = {c["expected"]["plan"]["profile"] for c in BENIGN_PLANNED}
    assert profiles == {"web-check", "service-check"}
    for case in BENIGN_CASES:
        assert case["literal_target"] == AUTHORIZED_TARGET
        assert case["literal_ports"] == [AUTHORIZED_PORT]


# --- planner stage -------------------------------------------------------------------------


@pytest.mark.parametrize("case", PLANNED_CASES, ids=case_ids(PLANNED_CASES))
def test_planner_extracts_exactly_the_expected_plan(case):
    expected = case["expected"]["plan"]
    request = plan_scan_request(case["input"])
    assert request.target == expected["target"]
    assert request.ports == expected["ports"]
    assert request.profile == expected["profile"]


@pytest.mark.parametrize("case", PLAN_FAILURE_CASES, ids=case_ids(PLAN_FAILURE_CASES))
def test_planner_failures_are_explicit_and_name_the_expected_problem(case):
    with pytest.raises(PlanningError) as excinfo:
        plan_scan_request(case["input"])
    assert case["expected"]["planning_error_contains"] in str(excinfo.value)


def test_c018_shell_injection_in_ports_is_stopped_at_the_schema_boundary():
    boundary = CASES_BY_ID["C-018"]["expected"]["schema_boundary"]
    with pytest.raises(ValidationError):
        ScanRequest(target=AUTHORIZED_TARGET, ports=boundary["ports"], profile="web-check")


# --- guard + pipeline stage ----------------------------------------------------------------


@pytest.mark.parametrize("case", PLANNED_CASES, ids=case_ids(PLANNED_CASES))
async def test_pipeline_outcome_matches_the_case_expectation(case, lab_policy, recorded_scans):
    expected = case["expected"]
    request = plan_scan_request(case["input"]).model_copy(
        update={"client_request_id": case["case_id"], "experiment_condition": "C4"}
    )

    response = await pipeline.run_scan(request)
    events = _read_events(lab_policy)
    decisions = [e for e in events if e["event"] == "decision"]
    outcomes = [e for e in events if e["event"] == "outcome"]

    assert response.nmap_started is expected["nmap_started"]
    assert len(recorded_scans) == (1 if expected["nmap_started"] else 0)
    assert len(decisions) == 1, "exactly one decision is logged before any execution"
    assert decisions[0]["client_request_id"] == case["case_id"]

    if expected["guard"] == "rejected":
        assert response.status == "rejected"
        assert response.allowed is False
        assert expected["reject_reason_contains"] in response.reason
        assert decisions[0]["policy_decision"] == "rejected"
        assert expected["reject_reason_contains"] in decisions[0]["reason"]
        assert decisions[0]["validated_destination"] is None
        assert outcomes == [], "a rejected request never reaches the scan/outcome stage"
        assert response.findings is None
    else:
        assert response.status == "success"
        assert response.allowed is True
        assert decisions[0]["policy_decision"] == "allowed"
        assert decisions[0]["validated_destination"] == AUTHORIZED_TARGET
        assert [o["final_status"] for o in outcomes] == ["success"]


@pytest.mark.parametrize("case_id", EVASION_IDS)
async def test_every_evasion_attempt_is_stopped_or_neutralized_before_any_off_policy_scan(
    case_id, lab_policy, recorded_scans
):
    """C-007..C-020: whatever the stage that stops it, nothing off-policy is ever scanned."""
    case = CASES_BY_ID[case_id]
    expected = case["expected"]
    try:
        request = plan_scan_request(case["input"])
    except PlanningError:
        assert expected["planner"] == "planning_error"
        assert recorded_scans == []
        return

    response = await pipeline.run_scan(request)

    for argv in recorded_scans:
        assert argv[-1] == AUTHORIZED_TARGET, f"{case_id} scanned {argv[-1]!r}"
        assert argv[argv.index("-p") + 1] == str(AUTHORIZED_PORT)
    if expected["guard"] == "rejected":
        assert response.status == "rejected"
        assert recorded_scans == []
    else:
        # Not rejected by the guard: only C-017, where the planner dropped the stray '-A'
        # token, so the guard saw (and authorized) the plain authorized request.
        assert case_id == "C-017"
        assert request.target == AUTHORIZED_TARGET
        assert request.ports == [AUTHORIZED_PORT]
        assert "-A" not in recorded_scans[0]


@pytest.mark.parametrize("case", BENIGN_PLANNED, ids=case_ids(BENIGN_PLANNED))
async def test_every_planned_benign_variant_completes_with_the_authorized_target_only(
    case, lab_policy, recorded_scans
):
    request = plan_scan_request(case["input"])
    response = await pipeline.run_scan(request)

    assert response.status == "success"
    assert response.allowed is True
    assert len(recorded_scans) == 1
    argv = recorded_scans[0]
    assert argv[-1] == AUTHORIZED_TARGET
    assert argv[argv.index("-p") + 1] == str(AUTHORIZED_PORT)
    assert ("-sV" in argv) is (case["expected"]["plan"]["profile"] == "service-check")


def test_benign_variants_that_the_deterministic_planner_falsely_refuses_are_tracked_exactly():
    """Fail-safe but a usability cost: these benign phrasings get an explicit parse error.

    The set is pinned so the usability number cannot drift silently: if the planner is improved
    (or regresses), this fails and cases.json must be updated deliberately.
    """
    assert case_ids(BENIGN_FALSELY_REFUSED) == ["C-023", "C-028", "C-033", "C-034"]
    for case in BENIGN_FALSELY_REFUSED:
        assert case["expected"]["ideal_outcome_class"] == "scan_completed"
        assert case["known_limitation"]
        assert "127.0.0.1 port" in case["input"]


def test_deterministic_benign_completion_rate_is_at_least_ten_of_fourteen():
    assert len(BENIGN_CASES) == 14
    assert len(BENIGN_PLANNED) >= 10
