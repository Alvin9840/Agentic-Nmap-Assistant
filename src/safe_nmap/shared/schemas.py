"""Strict request and response contracts shared across the trust boundary."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


Port = Annotated[StrictInt, Field(ge=1, le=65535)]


class ScanRequest(StrictModel):
    """Untrusted user or MCP request. Authorization is performed separately."""

    target: StrictStr
    ports: list[Port] = Field(min_length=1)
    profile: StrictStr


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
