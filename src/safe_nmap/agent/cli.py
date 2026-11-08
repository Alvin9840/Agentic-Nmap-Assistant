"""Command-line entry point for the Safe Nmap Assistant."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from uuid import uuid4

from mcp import MCPError, StdioServerParameters

from safe_nmap.agent.llm_planner import LLMPlanner, LLMUnavailableError
from safe_nmap.agent.mcp_client import MCPClient
from safe_nmap.agent.pipeline import Planner, run_scan
from safe_nmap.agent.planner import PlanningError, plan_scan_request
from safe_nmap.server import audit, reporter
from safe_nmap.shared.schemas import ScanRequest, ScanResponse


class _PlannerContext:
    """Tracks which planner mode produced the request sent to the server.

    ``choose_planner`` wraps the selected planner so the wrapper can record
    the mode actually used (relevant for ``auto``, where the LLM planner may
    fall back to the deterministic one per-request) and the final
    ``ScanRequest`` for display and audit logging.
    """

    def __init__(self, requested_mode: str) -> None:
        self.mode = requested_mode
        self.request: ScanRequest | None = None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="safe-nmap",
        description="Request an authorized Nmap scan through the policy-guarded MCP server.",
    )
    parser.add_argument(
        "--planner",
        choices=("auto", "llm", "deterministic"),
        default="auto",
        help=(
            "Planner mode: auto prefers the LLM and falls back only if it is unavailable; "
            "llm disables fallback; deterministic uses the rule-based parser."
        ),
    )
    parser.add_argument(
        "--request",
        required=True,
        help="Natural-language scan request.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the raw structured ScanResponse instead of the rendered report.",
    )
    return parser.parse_args(argv)


def choose_planner(mode: str, context: _PlannerContext) -> Planner:
    """Select the requested planner and apply fallback only in auto mode."""

    def _finalize(request: ScanRequest, used_mode: str) -> ScanRequest:
        if request.client_request_id is None:
            request = request.model_copy(update={"client_request_id": str(uuid4())})
        context.mode = used_mode
        context.request = request
        return request

    if mode == "deterministic":
        return lambda text: _finalize(plan_scan_request(text), "deterministic")

    try:
        llm_planner = LLMPlanner().plan_scan_request
    except LLMUnavailableError as exc:
        if mode == "llm":
            raise
        _warn_fallback(exc)
        return lambda text: _finalize(plan_scan_request(text), "deterministic")

    if mode == "llm":
        return lambda text: _finalize(llm_planner(text), "llm")

    def plan_with_fallback(user_text: str) -> ScanRequest:
        try:
            return _finalize(llm_planner(user_text), "llm")
        except LLMUnavailableError as exc:
            _warn_fallback(exc)
            return _finalize(plan_scan_request(user_text), "deterministic")

    return plan_with_fallback


def _warn_fallback(reason: Exception) -> None:
    print(
        f"Warning: the LLM planner is unavailable; using the deterministic planner. ({reason})",
        file=sys.stderr,
    )


def create_server_parameters() -> StdioServerParameters:
    """Build fixed stdio launch parameters for the project MCP server."""
    project_root = Path(__file__).resolve().parents[3]
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "safe_nmap.server.mcp_server"],
        cwd=project_root,
    )


def _write_planner_audit_event(context: _PlannerContext) -> None:
    """Best-effort agent-side audit event; correlates with the server's events
    through ``client_request_id``, which the server echoes into its own log."""
    if context.request is None:
        return
    audit.log_outcome_event(
        {
            "event": "planner",
            "client_request_id": context.request.client_request_id,
            "timestamp": audit.utc_timestamp(),
            "planner_mode": context.mode,
            "proposed_plan": {
                "target": context.request.target,
                "ports": context.request.ports,
                "profile": context.request.profile,
            },
        }
    )


async def run_cli_request(
    request_text: str, planner_mode: str
) -> tuple[ScanResponse, _PlannerContext]:
    context = _PlannerContext(planner_mode)
    planner = choose_planner(planner_mode, context)
    mcp_client = MCPClient(create_server_parameters())
    response = await run_scan(request_text, planner, mcp_client)
    _write_planner_audit_event(context)
    return response, context


def display_response(response: ScanResponse, profile: str | None, as_json: bool) -> None:
    if as_json:
        print(response.model_dump_json(indent=2))
    else:
        print(reporter.render_report(response, profile=profile))


def main() -> None:
    args = parse_args()
    try:
        response, context = asyncio.run(run_cli_request(args.request, args.planner))
    except PlanningError as exc:
        print(f"Planning error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    except (MCPError, OSError, RuntimeError) as exc:
        print(f"MCP client error: {exc}", file=sys.stderr)
        raise SystemExit(1) from None

    profile = context.request.profile if context.request is not None else None
    display_response(response, profile, args.json)


if __name__ == "__main__":
    main()
