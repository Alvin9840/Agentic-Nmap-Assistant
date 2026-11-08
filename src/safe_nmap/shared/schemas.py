"""Strict request and response contracts shared across the trust boundary."""

import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


Port = Annotated[StrictInt, Field(ge=1, le=65535)]

# Metadata fields are logging/experiment labels only; the policy guard never
# uses them for authorization decisions.
_METADATA_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def _validate_metadata_label(value: str | None) -> str | None:
    if value is not None and not _METADATA_PATTERN.fullmatch(value):
        raise ValueError("must contain 1-64 characters from [A-Za-z0-9_.-]")
    return value


class ScanRequest(StrictModel):
    """Untrusted user or MCP request. Authorization is performed separately."""

    target: StrictStr
    ports: list[Port] = Field(min_length=1)
    profile: StrictStr
    client_request_id: StrictStr | None = None
    experiment_condition: StrictStr | None = None

    @field_validator("client_request_id", "experiment_condition")
    @classmethod
    def _validate_metadata_fields(cls, value: str | None) -> str | None:
        return _validate_metadata_label(value)


class ValidatedPlan(StrictModel):
    """Server-created plan that is safe to pass to the scanner."""

    original_target: StrictStr
    resolved_ip: StrictStr
    ports: list[Port] = Field(min_length=1)
    profile: StrictStr
    timeout_seconds: StrictInt = Field(gt=0)
    service_detection: bool


class Finding(StrictModel):
    port: StrictInt = Field(ge=1, le=65535)
    protocol: StrictStr
    state: StrictStr
    service: StrictStr | None = None
    product: StrictStr | None = None
    version: StrictStr | None = None


ScanStatus = Literal["success", "parse_error", "rejected", "scan_failed"]


class ScanResponse(StrictModel):
    request_id: StrictStr
    status: ScanStatus
    allowed: bool
    nmap_started: bool
    reason: StrictStr | None = None
    target: StrictStr
    resolved_ip: StrictStr | None = None
    findings: list[Finding] | None = None
    policy_ms: float | None = None
    scan_ms: float | None = None
    server_total_ms: float | None = None
