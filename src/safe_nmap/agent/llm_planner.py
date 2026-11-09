"""OpenAI-backed planner that converts natural language to a ScanRequest."""

from __future__ import annotations

import json
import os
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI, OpenAIError
from pydantic import BaseModel, ConfigDict, StrictStr, ValidationError

from safe_nmap.agent.planner import PlanningError
from safe_nmap.agent.prompts import (
    C2_PLANNER_INSTRUCTIONS,
    C3_PLANNER_INSTRUCTIONS,
    LLM_PLANNER_INSTRUCTIONS,
)
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

    def __init__(
            self,
            model: str | None = None,
            client: Any | None = None,
            condition: str = "C4",
    ) -> None:

        prompts = {
            "C2": C2_PLANNER_INSTRUCTIONS,
            "C3": C3_PLANNER_INSTRUCTIONS,
            "C4": LLM_PLANNER_INSTRUCTIONS,
        }

        if condition not in prompts:
            raise ValueError(f"Unknown experiment condition: {condition}")

        self._instructions = prompts[condition]
        load_dotenv()
        self._model = model or os.getenv("OPENAI_MODEL")
        if not self._model:
            raise LLMUnavailableError("Set OPENAI_MODEL before using the LLM planner.")

        if client is not None:
            self._client = client
        else:
            if not os.getenv("OPENAI_API_KEY"):
                raise LLMUnavailableError("Set OPENAI_API_KEY before using the LLM planner.")
            self._client = OpenAI(
                api_key=os.getenv("OPENAI_API_KEY"),
                base_url=os.getenv("OPENAI_BASE_URL") or "https://api.openai.com/v1",
            )

    def plan_scan_request(self, user_text: str) -> ScanRequest:
        """Return a validated request or ask the caller to clarify missing fields."""
        if not isinstance(user_text, str) or not user_text.strip():
            raise PlanningError("Provide a scan request.")

        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {
                        "role": "system",
                        "content": self._instructions,
                    },
                    {
                        "role": "user",
                        "content": user_text,
                    },
                ],
                response_format={"type": "json_object"},
                max_tokens=500,
            )
        except OpenAIError as exc:
            raise LLMUnavailableError(
                "The LLM service is unavailable or rejected the request."
            ) from exc
        except ValidationError as exc:
            message = "The LLM planner could not produce a valid structured response."
            raise PlanningError(message) from exc


        content = response.choices[0].message.content

        if not content:
            raise PlanningError(
                "The LLM planner returned an empty response."
            )

        try:
            parsed = PlannerOutput.model_validate(json.loads(content))
        except (json.JSONDecodeError, ValidationError) as exc:
            raise PlanningError(
                "The LLM planner did not return valid structured scan parameters."
            ) from exc
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
