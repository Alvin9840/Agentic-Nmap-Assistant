"""Matched latency experiment (README section 16).

Repeats the SAME authorized plan at least ``--repeats`` times through the
real production path (deterministic planner -> in-process
``server.pipeline.run_scan``, i.e. policy guard -> command builder ->
scanner -> parser) and records planner/policy/scan/total time for each run.

This measures the deterministic planner, not the LLM planner (no API key is
configured in this environment); label all reported numbers accordingly and
do not present them as LLM-planner latency.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import os
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from safe_nmap.agent.planner import plan_scan_request
from safe_nmap.server import policy_config
from safe_nmap.server.pipeline import run_scan

DEFAULT_REQUEST_TEXT = "profile web-check port 8080 target 127.0.0.1"
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "results" / "latency_raw.csv"
CSV_FIELDS = ["run_index", "planner_ms", "policy_ms", "scan_ms", "server_total_ms", "status"]


@dataclass
class LatencyRun:
    run_index: int
    planner_ms: float
    policy_ms: float | None
    scan_ms: float | None
    server_total_ms: float | None
    status: str

    def as_row(self) -> dict:
        return {name: getattr(self, name) for name in CSV_FIELDS}


async def run_once(request_text: str, run_index: int) -> LatencyRun:
    planner_started_at = time.perf_counter()
    request = plan_scan_request(request_text)
    planner_ms = (time.perf_counter() - planner_started_at) * 1000

    response = await run_scan(request)
    return LatencyRun(
        run_index=run_index,
        planner_ms=planner_ms,
        policy_ms=response.policy_ms,
        scan_ms=response.scan_ms,
        server_total_ms=response.server_total_ms,
        status=response.status,
    )


async def run_all(request_text: str, repeats: int, policy_path: Path) -> list[LatencyRun]:
    policy_config.reset_policy_cache()
    os.environ["SAFE_NMAP_POLICY"] = str(policy_path)

    runs: list[LatencyRun] = []
    for index in range(1, repeats + 1):
        runs.append(await run_once(request_text, index))
    return runs


def write_csv(runs: list[LatencyRun], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for run in runs:
            writer.writerow(run.as_row())


def summarize(runs: list[LatencyRun]) -> dict[str, dict[str, float]]:
    """Return n/mean/std for each phase, over successful runs only."""
    successful = [run for run in runs if run.status == "success"]
    summary: dict[str, dict[str, float]] = {}
    for field_name in ("planner_ms", "policy_ms", "scan_ms", "server_total_ms"):
        values = [getattr(run, field_name) for run in successful if getattr(run, field_name) is not None]
        if not values:
            summary[field_name] = {"n": 0, "mean": float("nan"), "std": float("nan")}
            continue
        summary[field_name] = {
            "n": len(values),
            "mean": statistics.mean(values),
            "std": statistics.stdev(values) if len(values) > 1 else 0.0,
        }
    return summary


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", default=DEFAULT_REQUEST_TEXT)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    parser.add_argument(
        "--policy", type=Path, default=PROJECT_ROOT / "config" / "policy.example.yaml"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    runs = asyncio.run(run_all(args.request, args.repeats, args.policy))
    write_csv(runs, args.output)

    summary = summarize(runs)
    failed = [run for run in runs if run.status != "success"]
    print(f"Wrote {len(runs)} rows to {args.output} ({len(failed)} non-success runs)")
    for field_name, stats in summary.items():
        print(f"{field_name}: n={stats['n']} mean={stats['mean']:.3f}ms std={stats['std']:.3f}ms")


if __name__ == "__main__":
    main()
