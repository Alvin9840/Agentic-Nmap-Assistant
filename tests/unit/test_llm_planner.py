
"""Unit tests for the LLM planner using a mocked API client."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
from openai import OpenAIError

from safe_nmap.agent import llm_planner
from safe_nmap.agent.llm_planner import (
    LLMPlanner,
    LLMUnavailableError,
    PlannerOutput,
)
from safe_nmap.agent.planner import PlanningError
from safe_nmap.agent.prompts import (
    C2_PLANNER_INSTRUCTIONS,
    C3_PLANNER_INSTRUCTIONS,
    LLM_PLANNER_INSTRUCTIONS,
)


def _client_returning(parsed: PlannerOutput | None) -> MagicMock:
    client = MagicMock()

    content = (
        json.dumps(parsed.model_dump())
        if parsed is not None
        else None
    )

    client.chat.completions.create.return_value = MagicMock(
        choices=[
            MagicMock(
                message=MagicMock(content=content)
            )
        ]
    )
    return client


def test_llm_planner_requires_a_model(monkeypatch):
    monkeypatch.setattr(llm_planner, "load_dotenv", lambda: None)
    monkeypatch.delenv("OPENAI_MODEL", raising=False)

    with pytest.raises(LLMUnavailableError):
        LLMPlanner()


def test_llm_planner_requires_an_api_key_without_an_injected_client(
    monkeypatch,
):
    monkeypatch.setattr(llm_planner, "load_dotenv", lambda: None)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(LLMUnavailableError):
        LLMPlanner(model="gpt-oss-120b")


def test_llm_planner_accepts_an_injected_client_without_env_vars(
    monkeypatch,
):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    client = _client_returning(
        PlannerOutput(
            target="127.0.0.1",
            ports=[8080],
            profile="web-check",
        )
    )

    planner = LLMPlanner(model="gpt-oss-120b", client=client)
    request = planner.plan_scan_request("scan my web server")

    assert request.target == "127.0.0.1"
    assert request.ports == [8080]
    assert request.profile == "web-check"


def test_llm_planner_preserves_the_extracted_target_verbatim():
    client = _client_returning(
        PlannerOutput(
            target="10.0.0.9",
            ports=[22],
            profile="web-check",
        )
    )

    planner = LLMPlanner(model="gpt-oss-120b", client=client)
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
    planner = LLMPlanner(model="gpt-oss-120b", client=client)

    with pytest.raises(PlanningError):
        planner.plan_scan_request("an ambiguous request")


def test_llm_planner_raises_planning_error_on_empty_response():
    client = _client_returning(None)
    planner = LLMPlanner(model="gpt-oss-120b", client=client)

    with pytest.raises(PlanningError):
        planner.plan_scan_request("nonsense")


def test_llm_planner_wraps_openai_errors_as_unavailable():
    client = MagicMock()
    client.chat.completions.create.side_effect = OpenAIError(
        "service unavailable"
    )

    planner = LLMPlanner(model="gpt-oss-120b", client=client)

    with pytest.raises(LLMUnavailableError):
        planner.plan_scan_request("scan 127.0.0.1")


def test_llm_planner_wraps_validation_errors_as_planning_errors():
    client = MagicMock()
    client.chat.completions.create.return_value = MagicMock(
        choices=[
            MagicMock(
                message=MagicMock(content='{"target": 123}')
            )
        ]
    )

    planner = LLMPlanner(model="gpt-oss-120b", client=client)

    with pytest.raises(PlanningError):
        planner.plan_scan_request("scan 127.0.0.1")


def test_llm_planner_rejects_empty_text_without_calling_the_client():
    client = MagicMock()
    planner = LLMPlanner(model="gpt-oss-120b", client=client)

    with pytest.raises(PlanningError):
        planner.plan_scan_request("   ")

    client.chat.completions.create.assert_not_called()


@pytest.mark.parametrize(
    ("condition", "expected_prompt"),
    [
        ("C2", C2_PLANNER_INSTRUCTIONS),
        ("C3", C3_PLANNER_INSTRUCTIONS),
        ("C4", LLM_PLANNER_INSTRUCTIONS),
    ],
)
def test_llm_planner_selects_correct_prompt(condition, expected_prompt):
    client = _client_returning(
        PlannerOutput(
            target="127.0.0.1",
            ports=[8080],
            profile="web-check",
        )
    )

    planner = LLMPlanner(
        model="gpt-oss-120b",
        client=client,
        condition=condition,
    )

    planner.plan_scan_request("scan 127.0.0.1 port 8080")

    arguments = client.chat.completions.create.call_args.kwargs
    assert arguments["messages"][0]["content"] == expected_prompt


def test_llm_planner_rejects_unknown_condition():
    with pytest.raises(ValueError):
        LLMPlanner(
            model="gpt-oss-120b",
            client=MagicMock(),
            condition="C5",
        )
