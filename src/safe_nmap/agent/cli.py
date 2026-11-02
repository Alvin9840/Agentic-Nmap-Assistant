"""Command-line entry point for the Safe Nmap Assistant."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from mcp import MCPError, StdioServerParameters

from safe_nmap.agent.llm_planner import LLMPlanner, LLMUnavailableError
from safe_nmap.agent.mcp_client import MCPClient
from safe_nmap.agent.pipeline import Planner, run_scan
from safe_nmap.agent.planner import PlanningError, plan_scan_request
from safe_nmap.shared.schemas import ScanRequest, ScanResponse


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
    return parser.parse_args(argv)


def choose_planner(mode: str) -> Planner:
    """Select the requested planner and apply fallback only in auto mode."""
    if mode == "deterministic":
        return plan_scan_request

    try:
        llm_planner = LLMPlanner().plan_scan_request
    except LLMUnavailableError as exc:
        if mode == "llm":
            raise
        _warn_fallback(exc)
        return plan_scan_request

    if mode == "llm":
        return llm_planner

    def plan_with_fallback(user_text: str) -> ScanRequest:
        try:
            return llm_planner(user_text)
        except LLMUnavailableError as exc:
            _warn_fallback(exc)
            return plan_scan_request(user_text)

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


async def run_cli_request(request_text: str, planner_mode: str) -> ScanResponse:
    planner = choose_planner(planner_mode)
    mcp_client = MCPClient(create_server_parameters())
    return await run_scan(request_text, planner, mcp_client)


def display_response(response: ScanResponse) -> None:
    """Display only fields present in the structured server response."""
    print(f"Status: {response.status}")
    print(f"Allowed: {'yes' if response.allowed else 'no'}")
    print(f"Nmap started: {'yes' if response.nmap_started else 'no'}")
    print(f"Target: {response.target}")
    if response.resolved_ip is not None:
        print(f"Resolved IP: {response.resolved_ip}")
    if response.reason:
        print(f"Reason: {response.reason}")

    if response.findings is None:
        print("Findings: unavailable because no valid scan result was returned.")
    elif not response.findings:
        print("Findings: none.")
    else:
        print("Findings:")
        for finding in response.findings:
            service_details = " ".join(
                value for value in (finding.product, finding.version) if value
            )
            service = finding.service or "unknown service"
            if service_details:
                service = f"{service} ({service_details})"
            print(f"  {finding.port}/{finding.protocol}: {finding.state}; {service}")


def main() -> None:
    args = parse_args()
    try:
        response = asyncio.run(run_cli_request(args.request, args.planner))
    except PlanningError as exc:
        print(f"Planning error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    except (MCPError, OSError, RuntimeError) as exc:
        print(f"MCP client error: {exc}", file=sys.stderr)
        raise SystemExit(1) from None

    display_response(response)


if __name__ == "__main__":
    main()
