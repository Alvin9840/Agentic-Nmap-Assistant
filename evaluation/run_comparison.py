"""C1-C4 comparison harness (README section 15).

Implemented and runnable without an LLM API key:

- C1 (manual Nmap): scripts a literal ``nmap`` command from each case's
  ``literal_target``/``literal_ports`` fields. Lab-only ground truth; bypasses
  the application entirely on purpose.
- C4 (production guard): runs the *real* deterministic planner, then the
  real in-process ``server.pipeline.run_scan`` (policy guard, command
  builder, scanner, parser). The MCP stdio hop is transport only and does
  not change the authorization decision (README section 9), so calling the
  pipeline directly is faithful to the production path while keeping the
  harness fast and dependency-free.

Not implemented in this environment:

- C2 (no application policy guard) and C3 (prompt-only restrictions) both
  require the same LLM planner/model used across conditions (README section
  15), and no ``OPENAI_API_KEY``/``OPENAI_MODEL`` is configured here. Rather
  than write and ship an untested "skip the policy guard" code path, this
  harness records an explicit ``not_run`` result for every case under C2/C3.
  Do not report C2/C3 numbers from this harness; they do not exist.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import ipaddress
import json
import os
import shutil
import socket
import sys
import time
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from outcomes import classify_planning_error, classify_row

from safe_nmap.agent.llm_planner import LLMPlanner, LLMUnavailableError
from safe_nmap.agent.planner import PlanningError, plan_scan_request
from safe_nmap.server import parser as nmap_parser
from safe_nmap.server import (
    policy_config,
    scanner,
)
from safe_nmap.server.pipeline import run_scan

DEFAULT_CASES_PATH = PROJECT_ROOT / "evaluation" / "cases.json"
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "results" / "comparison_raw.csv"
CSV_FIELDS = [
    "case_id",
    "category",
    "condition",
    "status",
    "policy_decision",
    "nmap_started",
    "destination",
    "ports",
    "findings",
    "reason",
    "duration_ms",
    "outcome_class",
]


@dataclass
class ComparisonRecord:
    case_id: str
    category: str
    condition: str
    status: str
    policy_decision: str | None = None
    nmap_started: bool | None = None
    destination: str | None = None
    ports: str | None = None
    findings: str | None = None
    reason: str | None = None
    duration_ms: float | None = None
    # Set explicitly where the exception type matters (model refusal vs. planning
    # failure); otherwise derived from status/policy_decision.
    outcome_class: str | None = None

    def as_row(self) -> dict:
        row = {name: getattr(self, name) for name in CSV_FIELDS}
        if row["outcome_class"] is None:
            row["outcome_class"] = str(classify_row(self.status, self.policy_decision))
        return row


def load_cases(path: Path = DEFAULT_CASES_PATH) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["cases"]


def _lab_is_available() -> bool:
    if shutil.which("nmap") is None:
        return False
    try:
        with socket.create_connection(("127.0.0.1", 8080), timeout=1.0):
            return True
    except OSError:
        return False


async def run_c1(case: dict) -> ComparisonRecord:
    """Manual, scripted Nmap using the case's literal target/ports (no guard).

    This bypasses the application's policy guard by design (that is the
    point of the C1 baseline), so it is the one place in this harness that
    could reach outside the lab. As a hard safety net, independent of
    anything in ``cases.json``, it refuses any target outside the loopback
    range (127.0.0.0/8) rather than trusting the case data.
    """
    target = case.get("literal_target")
    ports = case.get("literal_ports")
    if not target or not ports:
        return ComparisonRecord(
            case_id=case["case_id"],
            category=case["category"],
            condition="C1",
            status="not_applicable",
            reason="case has no single literal target/ports to script directly",
        )

    try:
        if not ipaddress.ip_address(target).is_loopback:
            raise ValueError("not a loopback address")
    except ValueError:
        return ComparisonRecord(
            case_id=case["case_id"],
            category=case["category"],
            condition="C1",
            status="refused_by_harness",
            reason=(
                f"refusing to run C1 (no guard) against {target!r}: only loopback "
                "(127.0.0.0/8) targets are permitted, regardless of cases.json"
            ),
        )

    arguments = [
        "nmap",
        "-n",
        "-sT",
        "-T3",
        "-oX",
        "-",
        "-p",
        ",".join(str(port) for port in ports),
        target,
    ]
    started_at = time.perf_counter()
    execution = await scanner.run_nmap(arguments, timeout_seconds=30)
    duration_ms = (time.perf_counter() - started_at) * 1000

    if not execution.nmap_started or execution.xml_output is None:
        return ComparisonRecord(
            case_id=case["case_id"],
            category=case["category"],
            condition="C1",
            status="scan_failed",
            nmap_started=execution.nmap_started,
            destination=target,
            ports=",".join(str(port) for port in ports),
            reason=execution.error_message,
            duration_ms=duration_ms,
        )

    try:
        findings = nmap_parser.parse_nmap_xml(execution.xml_output)
    except nmap_parser.NmapParseError as exc:
        return ComparisonRecord(
            case_id=case["case_id"],
            category=case["category"],
            condition="C1",
            status="parse_error",
            nmap_started=True,
            destination=target,
            ports=",".join(str(port) for port in ports),
            reason=str(exc),
            duration_ms=duration_ms,
        )

    states = ",".join(f"{finding.port}/{finding.state}" for finding in findings) or "no ports in output"
    return ComparisonRecord(
        case_id=case["case_id"],
        category=case["category"],
        condition="C1",
        status="success",
        nmap_started=True,
        destination=target,
        ports=",".join(str(port) for port in ports),
        findings=states,
        duration_ms=duration_ms,
    )


async def run_c4(
    case: dict,
    planner_mode: str = "deterministic",
) -> ComparisonRecord:
    """The real production path: deterministic planner -> policy guard -> scanner."""
    started_at = time.perf_counter()
    try:
        if planner_mode == "llm":
            planner = LLMPlanner(condition="C4")
            request = planner.plan_scan_request(case["input"])
        elif planner_mode == "deterministic":
            request = plan_scan_request(case["input"])
        else:
            raise ValueError(f"Unknown planner mode: {planner_mode}")

    except PlanningError as exc:
        return ComparisonRecord(
            case_id=case["case_id"],
            category=case["category"],
            condition="C4",
            status="parse_error",
            policy_decision="not_reached",
            nmap_started=False,
            reason=str(exc),
            duration_ms=(time.perf_counter() - started_at) * 1000,
            outcome_class=str(classify_planning_error(exc)),
        )

    # Label the audit log with the case/condition so results can be traced
    # back to this run without relying on timing alone.
    request = request.model_copy(
        update={"client_request_id": case["case_id"], "experiment_condition": "C4"}
    )
    response = await run_scan(request)
    duration_ms = (time.perf_counter() - started_at) * 1000
    findings = None
    if response.findings is not None:
        findings = (
            ",".join(f"{finding.port}/{finding.state}" for finding in response.findings)
            or "no ports in output"
        )
    return ComparisonRecord(
        case_id=case["case_id"],
        category=case["category"],
        condition="C4",
        status=response.status,
        policy_decision="allowed" if response.allowed else "rejected",
        nmap_started=response.nmap_started,
        destination=response.resolved_ip,
        ports=",".join(str(port) for port in request.ports),
        findings=findings,
        reason=response.reason,
        duration_ms=duration_ms,
    )



def run_c2_or_c3(case: dict, condition: str) -> ComparisonRecord:
    """Evaluate LLM planning without executing an Nmap scan."""
    start_time = time.perf_counter()

    try:
        planner = LLMPlanner(condition=condition)
        request = planner.plan_scan_request(case["input"])

        duration_ms = (time.perf_counter() - start_time) * 1000

        return ComparisonRecord(
            case_id=case["case_id"],
            category=case["category"],
            condition=condition,
            status="plan_generated",
            policy_decision="not_evaluated",
            nmap_started=False,
            destination=request.target,
            ports=",".join(str(p) for p in request.ports),
            reason=f"Profile: {request.profile}",
            duration_ms=duration_ms,
        )

    except LLMUnavailableError as exc:
        status = "llm_unavailable"
        reason = str(exc)
        outcome_class = None  # derived from status: planning_failure

    except PlanningError as exc:
        status = "planning_failed"
        reason = str(exc)
        outcome_class = str(classify_planning_error(exc))

    return ComparisonRecord(
        case_id=case["case_id"],
        category=case["category"],
        condition=condition,
        status=status,
        policy_decision="not_evaluated",
        nmap_started=False,
        reason=reason,
        duration_ms=(time.perf_counter() - start_time) * 1000,
        outcome_class=outcome_class,
    )



async def run_all(
    cases: list[dict],
    conditions: list[str],
    policy_path: Path,
    planner_mode: str = "deterministic",
) -> list[ComparisonRecord]:
    policy_config.reset_policy_cache()
    os.environ["SAFE_NMAP_POLICY"] = str(policy_path)

    records: list[ComparisonRecord] = []
    for case in cases:
        if "C1" in conditions:
            records.append(await run_c1(case))
        if "C2" in conditions:
            records.append(run_c2_or_c3(case, "C2"))
        if "C3" in conditions:
            records.append(run_c2_or_c3(case, "C3"))
        if "C4" in conditions:
            records.append(await run_c4(case, planner_mode=planner_mode))
    return records


def write_csv(records: list[ComparisonRecord], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for record in records:
            writer.writerow(record.as_row())


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES_PATH)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    parser.add_argument(
        "--conditions",
        default="C1,C4",
        help="Comma-separated subset of C1,C2,C3,C4 (default: C1,C4; C2/C3 are not implemented).",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=PROJECT_ROOT / "config" / "policy.example.yaml",
        help="Policy file used for the C4 condition.",
    )

    parser.add_argument(
        "--planner",
        choices=["deterministic", "llm"],
        default="deterministic",
        help="Planner used for C4 (default: deterministic).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    conditions = [c.strip().upper() for c in args.conditions.split(",") if c.strip()]
    cases = load_cases(args.cases)

    if "C1" in conditions and not _lab_is_available():
        print(
            "Warning: nmap and/or the Docker lab (127.0.0.1:8080) are unavailable; "
            "C1 cases will fail rather than being silently skipped.",
            file=sys.stderr,
        )

    records = asyncio.run(
        run_all(
            cases,
            conditions,
            args.policy,
            planner_mode=args.planner,
        )
    )
    write_csv(records, args.output)
    print(f"Wrote {len(records)} rows to {args.output}")


if __name__ == "__main__":
    main()
