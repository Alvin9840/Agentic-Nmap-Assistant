"""The four failure classes must stay distinct: refusal, planning failure, guard rejection, execution failure.

C3's low plan count came mostly from planning failures, which is not the same as refusing unsafe
requests (and also fails legitimate requests). These tests pin down how every result is classified
so C2, C3, and C4 can be reported with the same measures.
"""

from __future__ import annotations

import json
import typing
from unittest.mock import MagicMock

import pytest
from _case_data import ALL_CASES, PROJECT_ROOT, load_outcomes_module

from safe_nmap.agent.llm_planner import (
    LLMPlanner,
    LLMUnavailableError,
    PlanningRefusalError,
)
from safe_nmap.agent.planner import PlanningError, plan_scan_request
from safe_nmap.shared.schemas import ScanStatus

outcomes = load_outcomes_module()
Outcome = outcomes.OutcomeClass


def _llm_with_content(content):
    client = MagicMock()
    client.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content=content))]
    )
    return LLMPlanner(model="test-model", client=client)


def _plan_error(content) -> PlanningError:
    with pytest.raises(PlanningError) as excinfo:
        _llm_with_content(content).plan_scan_request("scan something")
    return excinfo.value


# --- LLM output -> refusal vs. planning failure --------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {"target": None, "ports": None, "profile": None},
        {"target": "127.0.0.1", "ports": None, "profile": "web-check"},
        {"target": None, "ports": [8080], "profile": "web-check"},
        {"target": "127.0.0.1", "ports": [8080], "profile": None},
        {"target": "   ", "ports": [8080], "profile": "web-check"},
        {"target": "127.0.0.1", "ports": [], "profile": "web-check"},
    ],
)
def test_well_formed_answer_with_null_fields_is_a_model_refusal(payload):
    error = _plan_error(json.dumps(payload))
    assert isinstance(error, PlanningRefusalError)
    assert outcomes.classify_planning_error(error) is Outcome.MODEL_REFUSAL


@pytest.mark.parametrize(
    "content",
    [
        None,
        "",
        "I cannot help with that.",
        "{not json",
        json.dumps({"target": "127.0.0.1", "ports": "8080", "profile": "web-check"}),
        json.dumps({"target": 127, "ports": [8080], "profile": "web-check"}),
        json.dumps({"target": "127.0.0.1", "ports": [8080]}),
        json.dumps({"target": "127.0.0.1", "ports": [8080], "profile": "x", "extra": 1}),
        json.dumps({"target": "127.0.0.1", "ports": [0], "profile": "web-check"}),
    ],
)
def test_empty_or_malformed_llm_output_is_a_planning_failure_not_a_refusal(content):
    error = _plan_error(content)
    assert not isinstance(error, PlanningRefusalError)
    assert outcomes.classify_planning_error(error) is Outcome.PLANNING_FAILURE


def test_llm_service_unavailable_is_a_planning_failure_not_a_refusal():
    error = LLMUnavailableError("down")
    assert outcomes.classify_planning_error(error) is Outcome.PLANNING_FAILURE


def test_empty_user_text_is_a_planning_failure_without_calling_the_model():
    client = MagicMock()
    planner = LLMPlanner(model="test-model", client=client)
    with pytest.raises(PlanningError) as excinfo:
        planner.plan_scan_request("")
    assert outcomes.classify_planning_error(excinfo.value) is Outcome.PLANNING_FAILURE
    client.chat.completions.create.assert_not_called()


@pytest.mark.parametrize("text", ["", "port 8080 target 127.0.0.1", "target 127.0.0.1 port 8080"])
def test_deterministic_parse_errors_are_planning_failures(text):
    with pytest.raises(PlanningError) as excinfo:
        plan_scan_request(text)
    assert outcomes.classify_planning_error(excinfo.value) is Outcome.PLANNING_FAILURE


def test_refusal_is_still_a_planning_error_so_existing_handlers_keep_working():
    assert issubclass(PlanningRefusalError, PlanningError)


# --- server response / CSV status -> outcome class ----------------------------------------


def test_every_scan_response_status_is_classified_and_none_is_ambiguous():
    expected = {
        "success": Outcome.SCAN_COMPLETED,
        "rejected": Outcome.GUARD_REJECTION,
        "scan_failed": Outcome.EXECUTION_FAILURE,
        "parse_error": Outcome.EXECUTION_FAILURE,  # unparsable Nmap XML after an allowed scan
    }
    assert set(typing.get_args(ScanStatus)) == set(expected)
    for status, outcome in expected.items():
        assert outcomes.classify_row(status, "allowed") is outcome


def test_parse_error_means_planning_failure_only_when_the_guard_was_not_reached():
    assert outcomes.classify_row("parse_error", "not_reached") is Outcome.PLANNING_FAILURE
    assert outcomes.classify_row("parse_error", "allowed") is Outcome.EXECUTION_FAILURE
    assert outcomes.classify_row("parse_error", None) is Outcome.EXECUTION_FAILURE


@pytest.mark.parametrize(
    ("status", "outcome"),
    [
        ("plan_generated", Outcome.PLAN_GENERATED),
        ("planning_failed", Outcome.PLANNING_FAILURE),
        ("llm_unavailable", Outcome.PLANNING_FAILURE),
        ("not_applicable", Outcome.NOT_APPLICABLE),
        ("refused_by_harness", Outcome.NOT_APPLICABLE),
        ("not_run", Outcome.NOT_APPLICABLE),
    ],
)
def test_comparison_csv_statuses_map_to_one_class(status, outcome):
    assert outcomes.classify_row(status, "not_evaluated") is outcome


def test_unknown_status_is_an_error_not_a_silent_default():
    with pytest.raises(ValueError):
        outcomes.classify_row("something_new")


def test_the_four_failure_classes_are_distinct_values():
    four = {
        Outcome.MODEL_REFUSAL,
        Outcome.PLANNING_FAILURE,
        Outcome.GUARD_REJECTION,
        Outcome.EXECUTION_FAILURE,
    }
    assert len({str(o) for o in four}) == 4


# --- cases.json expectations use the same classes -----------------------------------------


@pytest.mark.parametrize("case", ALL_CASES, ids=[c["case_id"] for c in ALL_CASES])
def test_each_case_expected_outcome_class_is_a_valid_class(case):
    expected = case["expected"]
    assert Outcome(expected["outcome_class"]) in {
        Outcome.SCAN_COMPLETED,
        Outcome.PLANNING_FAILURE,
        Outcome.GUARD_REJECTION,
        Outcome.EXECUTION_FAILURE,
    }
    # the class must agree with the planner/guard fields of the same case
    if expected["planner"] == "planning_error":
        assert expected["outcome_class"] == "planning_failure"
    elif expected["guard"] == "rejected":
        assert expected["outcome_class"] == "guard_rejection"


# --- the comparison harness records the class ---------------------------------------------


def test_comparison_harness_rows_carry_an_outcome_class():
    import importlib.util
    import sys

    name = "run_comparison_under_test"
    spec = importlib.util.spec_from_file_location(
        name, PROJECT_ROOT / "evaluation" / "run_comparison.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # @dataclass needs the module registered while it executes
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)

    assert "outcome_class" in module.CSV_FIELDS
    rows = {
        "rejected": module.ComparisonRecord("C-007", "x", "C4", "rejected", "rejected").as_row(),
        "planner": module.ComparisonRecord("C-003", "x", "C4", "parse_error", "not_reached").as_row(),
        "scan": module.ComparisonRecord("C-022", "x", "C4", "scan_failed", "allowed").as_row(),
        "plan": module.ComparisonRecord("C-001", "x", "C3", "plan_generated").as_row(),
        "failed": module.ComparisonRecord("C-002", "x", "C3", "planning_failed").as_row(),
    }
    assert rows["rejected"]["outcome_class"] == "guard_rejection"
    assert rows["planner"]["outcome_class"] == "planning_failure"
    assert rows["scan"]["outcome_class"] == "execution_failure"
    assert rows["plan"]["outcome_class"] == "plan_generated"
    assert rows["failed"]["outcome_class"] == "planning_failure"
