"""Unit tests for the LLM-backed planner, using a mocked OpenAI client.

No network access or API key is used: the OpenAI client is injected via the
constructor, and its ``responses.parse`` call is replaced with a stub.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from openai import OpenAIError
from pydantic import ValidationError

from safe_nmap.agent.llm_planner import LLMPlanner, LLMUnavailableError, PlannerOutput
from safe_nmap.agent.planner import PlanningError


def _client_returning(parsed: PlannerOutput | None) -> MagicMock:
    client = MagicMock()
    client.responses.parse.return_value = MagicMock(output_parsed=parsed)
    return client


def test_llm_planner_requires_a_model(monkeypatch):
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    with pytest.raises(LLMUnavailableError):
        LLMPlanner()


def test_llm_planner_requires_an_api_key_without_an_injected_client(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(LLMUnavailableError):
        LLMPlanner(model="gpt-4o-mini")


def test_llm_planner_accepts_an_injected_client_without_env_vars(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    client = _client_returning(PlannerOutput(target="127.0.0.1", ports=[8080], profile="web-check"))
    planner = LLMPlanner(model="gpt-4o-mini", client=client)
    request = planner.plan_scan_request("scan my web server")

    assert request.target == "127.0.0.1"
    assert request.ports == [8080]
    assert request.profile == "web-check"


def test_llm_planner_preserves_the_extracted_target_verbatim():
    client = _client_returning(PlannerOutput(target="10.0.0.9", ports=[22], profile="web-check"))
    planner = LLMPlanner(model="gpt-4o-mini", client=client)
    request = planner.plan_scan_request("scan 10.0.0.9")

    assert request.target == "10.0.0.9"


@pytest.mark.parametrize(
    "parsed",
    [
        PlannerOutput(target=None, ports=[8080], profile="web-check"),
        PlannerOutput(target="127.0.0.1", ports=None, profile="web-check"),
        PlannerOutput(target="127.0.0.1", ports=[8080], profile=None),
        PlannerOutput(target="  ", ports=[8080], profile="web-check"),
    ],
)
def test_llm_planner_raises_planning_error_on_missing_fields(parsed):
    client = _client_returning(parsed)
    planner = LLMPlanner(model="gpt-4o-mini", client=client)
    with pytest.raises(PlanningError):
        planner.plan_scan_request("an ambiguous request")


def test_llm_planner_raises_planning_error_when_output_parsed_is_none():
    client = _client_returning(None)
    planner = LLMPlanner(model="gpt-4o-mini", client=client)
    with pytest.raises(PlanningError):
        planner.plan_scan_request("nonsense")


def test_llm_planner_wraps_openai_errors_as_unavailable():
    client = MagicMock()
    client.responses.parse.side_effect = OpenAIError("service unavailable")
    planner = LLMPlanner(model="gpt-4o-mini", client=client)

    with pytest.raises(LLMUnavailableError):
        planner.plan_scan_request("scan 127.0.0.1")


def test_llm_planner_wraps_validation_errors_as_planning_errors():
    client = MagicMock()
    client.responses.parse.side_effect = ValidationError.from_exception_data(
        "PlannerOutput", []
    )
    planner = LLMPlanner(model="gpt-4o-mini", client=client)

    with pytest.raises(PlanningError):
        planner.plan_scan_request("scan 127.0.0.1")


def test_llm_planner_rejects_empty_text_without_calling_the_client():
    client = MagicMock()
    planner = LLMPlanner(model="gpt-4o-mini", client=client)

    with pytest.raises(PlanningError):
        planner.plan_scan_request("   ")

    client.responses.parse.assert_not_called()
