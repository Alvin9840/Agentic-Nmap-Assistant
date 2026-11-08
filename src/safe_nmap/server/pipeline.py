"""Coordinate authorization, Nmap execution, parsing, and response creation."""

from __future__ import annotations

import time
from uuid import uuid4

from safe_nmap.server import audit, command_builder, parser, policy_config, policy_guard, scanner
from safe_nmap.shared.schemas import ScanRequest, ScanResponse


class _ConcurrencyLimiter:
    """Non-blocking counting limiter for in-flight scans.

    Checking and incrementing the counter happens with no ``await`` in
    between, so this is atomic under cooperative asyncio scheduling without
    needing a separate lock.
    """

    def __init__(self, max_concurrent: int) -> None:
        self.max_concurrent = max_concurrent
        self._current = 0

    def try_acquire(self) -> bool:
        if self._current >= self.max_concurrent:
            return False
        self._current += 1
        return True

    def release(self) -> None:
        self._current = max(0, self._current - 1)


_concurrency_limiter: _ConcurrencyLimiter | None = None


def _get_concurrency_limiter(max_concurrent: int) -> _ConcurrencyLimiter:
    global _concurrency_limiter
    if _concurrency_limiter is None or _concurrency_limiter.max_concurrent != max_concurrent:
        _concurrency_limiter = _ConcurrencyLimiter(max_concurrent)
    return _concurrency_limiter


def _decision_event(
    request: ScanRequest,
    request_id: str,
    *,
    allowed: bool,
    reason: str | None,
    resolved_ip: str | None,
) -> dict:
    return {
        "event": "decision",
        "request_id": request_id,
        "timestamp": audit.utc_timestamp(),
        "client_request_id": request.client_request_id,
        "experiment_condition": request.experiment_condition,
        "original_request": {
            "target": request.target,
            "ports": request.ports,
            "profile": request.profile,
        },
        "policy_decision": "allowed" if allowed else "rejected",
        "reason": reason,
        "validated_destination": resolved_ip,
    }


def _outcome_event(request_id: str, response: ScanResponse) -> dict:
    return {
        "event": "outcome",
        "request_id": request_id,
        "timestamp": audit.utc_timestamp(),
        "final_status": response.status,
        "nmap_started": response.nmap_started,
        "timing": {
            "policy_ms": response.policy_ms,
            "scan_ms": response.scan_ms,
            "server_total_ms": response.server_total_ms,
        },
    }


async def run_scan(request: ScanRequest) -> ScanResponse:
    """Run one structured request through the server-side scan workflow."""
    request_id = str(uuid4())
    request_started_at = time.perf_counter()
    policy_started_at = request_started_at

    try:
        plan = policy_guard.authorize(request)
    except policy_guard.PolicyRejectedError as exc:
        policy_ms = _elapsed_ms(policy_started_at)
        audit.log_outcome_event(
            _decision_event(request, request_id, allowed=False, reason=str(exc), resolved_ip=None)
        )
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

    try:
        max_concurrent_scans = policy_config.get_policy().limits.max_concurrent_scans
    except policy_config.PolicyConfigError as exc:
        reason = f"Policy configuration is unavailable: {exc}"
        audit.log_outcome_event(
            _decision_event(
                request, request_id, allowed=False, reason=reason, resolved_ip=plan.resolved_ip
            )
        )
        return ScanResponse(
            request_id=request_id,
            status="rejected",
            allowed=False,
            nmap_started=False,
            reason=reason,
            target=request.target,
            resolved_ip=plan.resolved_ip,
            policy_ms=policy_ms,
            server_total_ms=_elapsed_ms(request_started_at),
        )

    limiter = _get_concurrency_limiter(max_concurrent_scans)
    if not limiter.try_acquire():
        reason = "too many concurrent scans"
        audit.log_outcome_event(
            _decision_event(
                request, request_id, allowed=False, reason=reason, resolved_ip=plan.resolved_ip
            )
        )
        return ScanResponse(
            request_id=request_id,
            status="rejected",
            allowed=False,
            nmap_started=False,
            reason=reason,
            target=request.target,
            resolved_ip=plan.resolved_ip,
            policy_ms=policy_ms,
            server_total_ms=_elapsed_ms(request_started_at),
        )

    try:
        # The decision event must be written before Nmap starts; a logging
        # failure here rejects the request instead of silently scanning.
        audit.write_event(
            _decision_event(
                request, request_id, allowed=True, reason=None, resolved_ip=plan.resolved_ip
            )
        )
    except audit.AuditWriteError as exc:
        limiter.release()
        return ScanResponse(
            request_id=request_id,
            status="rejected",
            allowed=False,
            nmap_started=False,
            reason=f"Audit logging failed; the scan was not started: {exc}",
            target=plan.original_target,
            resolved_ip=plan.resolved_ip,
            policy_ms=policy_ms,
            server_total_ms=_elapsed_ms(request_started_at),
        )

    try:
        arguments = command_builder.build_nmap_command(plan)
        execution = await scanner.run_nmap(arguments, plan.timeout_seconds)
    finally:
        limiter.release()

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
        response = ScanResponse(
            **response_fields,
            status="scan_failed",
            reason=execution.error_message or "Nmap did not start.",
            server_total_ms=_elapsed_ms(request_started_at),
        )
        audit.log_outcome_event(_outcome_event(request_id, response))
        return response

    if execution.xml_output is None:
        response = ScanResponse(
            **response_fields,
            status="scan_failed",
            reason="Nmap completed without returning XML output.",
            server_total_ms=_elapsed_ms(request_started_at),
        )
        audit.log_outcome_event(_outcome_event(request_id, response))
        return response

    try:
        findings = parser.parse_nmap_xml(execution.xml_output)
    except parser.NmapParseError as exc:
        response = ScanResponse(
            **response_fields,
            status="parse_error",
            reason=str(exc),
            server_total_ms=_elapsed_ms(request_started_at),
        )
        audit.log_outcome_event(_outcome_event(request_id, response))
        return response

    response = ScanResponse(
        **response_fields,
        status="success",
        findings=findings,
        server_total_ms=_elapsed_ms(request_started_at),
    )
    audit.log_outcome_event(_outcome_event(request_id, response))
    return response


def _elapsed_ms(started_at: float) -> float:
    return (time.perf_counter() - started_at) * 1000
