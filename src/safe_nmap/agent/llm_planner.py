"""OpenAI-backed planner that converts natural language to a ScanRequest."""

from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI, OpenAIError
from pydantic import BaseModel, ConfigDict, StrictStr, ValidationError

from safe_nmap.agent.planner import PlanningError
from safe_nmap.agent.prompts import LLM_PLANNER_INSTRUCTIONS
from safe_nmap.shared.schemas import Port, ScanRequest


class LLMUnavailableError(PlanningError):
    """Raised when the LLM planner cannot be configured or reached."""


class PlannerOutput(BaseModel):
    """Nullable extraction result; null fields signal that clarification is needed."""

    model_config = ConfigDict(extra="forbid", strict=True)

    target: StrictStr | None
    ports: list[Port] | None
    profile: StrictStr | None


class LLMPlanner:
    """Use an LLM only to interpret text; authorization remains server-side."""

    def __init__(self, model: str | None = None, client: Any | None = None) -> None:
        load_dotenv()
        self._model = model or os.getenv("OPENAI_MODEL")
        if not self._model:
            raise LLMUnavailableError("Set OPENAI_MODEL before using the LLM planner.")

        if client is not None:
            self._client = client
        else:
            if not os.getenv("OPENAI_API_KEY"):
                raise LLMUnavailableError("Set OPENAI_API_KEY before using the LLM planner.")
            self._client = OpenAI()

    def plan_scan_request(self, user_text: str) -> ScanRequest:
        """Return a validated request or ask the caller to clarify missing fields."""
        if not isinstance(user_text, str) or not user_text.strip():
            raise PlanningError("Provide a scan request.")

        try:
            response = self._client.responses.parse(
                model=self._model,
                instructions=LLM_PLANNER_INSTRUCTIONS,
                input=user_text,
                text_format=PlannerOutput,
                max_output_tokens=200,
            )
        except OpenAIError as exc:
            raise LLMUnavailableError(
                "The LLM service is unavailable or rejected the request."
            ) from exc
        except ValidationError as exc:
            message = "The LLM planner could not produce a valid structured response."
            raise PlanningError(message) from exc

        parsed = response.output_parsed
        if parsed is None:
            raise PlanningError("The LLM planner did not return structured scan parameters.")

        missing_fields = []
        if parsed.target is None or not parsed.target.strip():
            missing_fields.append("target")
        if not parsed.ports:
            missing_fields.append("ports")
        if parsed.profile is None or not parsed.profile.strip():
            missing_fields.append("profile")
        if missing_fields:
            fields = ", ".join(missing_fields)
            raise PlanningError(f"Please clarify the following required fields: {fields}.")

        try:
            return ScanRequest(
                target=parsed.target,
                ports=parsed.ports,
                profile=parsed.profile,
            )
        except ValidationError as exc:
            raise PlanningError("The LLM planner returned invalid scan parameters.") from exc
