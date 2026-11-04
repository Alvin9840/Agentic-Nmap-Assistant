"""Coordinate authorization, Nmap execution, parsing, and response creation."""

from __future__ import annotations

import time
from uuid import uuid4

from safe_nmap.server import command_builder, parser, policy_guard, scanner
from safe_nmap.shared.schemas import ScanRequest, ScanResponse


async def run_scan(request: ScanRequest) -> ScanResponse:
    """Run one structured request through the server-side scan workflow."""
    request_id = str(uuid4())
    request_started_at = time.perf_counter()
    policy_started_at = request_started_at

    try:
        plan = policy_guard.authorize(request)
    except policy_guard.PolicyRejectedError as exc:
        policy_ms = _elapsed_ms(policy_started_at)
        return ScanResponse(
            request_id=request_id,
            status="rejected",
            allowed=False,
            nmap_started=False,
            reason=str(exc),
            target=request.target,
            policy_ms=policy_ms,
            server_total_ms=_elapsed_ms(request_started_at),
        )

    policy_ms = _elapsed_ms(policy_started_at)
    arguments = command_builder.build_nmap_command(plan)
    execution = await scanner.run_nmap(arguments, plan.timeout_seconds)

    response_fields = {
        "request_id": request_id,
        "allowed": True,
        "nmap_started": execution.nmap_started,
        "target": plan.original_target,
        "resolved_ip": plan.resolved_ip,
        "policy_ms": policy_ms,
        "scan_ms": execution.scan_ms,
    }

    if not execution.nmap_started or execution.error_message is not None:
        return ScanResponse(
            **response_fields,
            status="scan_failed",
            reason=execution.error_message or "Nmap did not start.",
            server_total_ms=_elapsed_ms(request_started_at),
        )

    if execution.xml_output is None:
        return ScanResponse(
            **response_fields,
            status="scan_failed",
            reason="Nmap completed without returning XML output.",
            server_total_ms=_elapsed_ms(request_started_at),
        )

    try:
        findings = parser.parse_nmap_xml(execution.xml_output)
    except parser.NmapParseError as exc:
        return ScanResponse(
            **response_fields,
            status="parse_error",
            reason=str(exc),
            server_total_ms=_elapsed_ms(request_started_at),
        )

    return ScanResponse(
        **response_fields,
        status="success",
        findings=findings,
        server_total_ms=_elapsed_ms(request_started_at),
    )


def _elapsed_ms(started_at: float) -> float:
    return (time.perf_counter() - started_at) * 1000
