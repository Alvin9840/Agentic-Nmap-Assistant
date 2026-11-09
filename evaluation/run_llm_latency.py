
"""Measure end-to-end LLM + Policy Guard + Nmap latency."""
import asyncio
import csv
import os
import statistics
import time
from pathlib import Path

from openai import OpenAIError

from safe_nmap.agent.llm_planner import LLMPlanner, LLMUnavailableError
from safe_nmap.agent.planner import PlanningError
from safe_nmap.server import policy_config
from safe_nmap.server.pipeline import run_scan


def write_results(output, fields, rows):
    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

async def main():
    os.environ["SAFE_NMAP_POLICY"] = str(
        Path("config/policy.example.yaml").resolve()
    )
    policy_config.reset_policy_cache()

    output = Path("results/latency_llm.csv")
    output.parent.mkdir(parents=True, exist_ok=True)

    planner = LLMPlanner(condition="C4")
    rows = []

    for index in range(1, 11):
        started = time.perf_counter()

        try:
            request = planner.plan_scan_request(
                "profile web-check port 8080 target 127.0.0.1"
            )
            planner_ms = (time.perf_counter() - started) * 1000

            response = await run_scan(request)
            total_ms = (time.perf_counter() - started) * 1000

            row = {
                "run": index,
                "status": response.status,
                "planner_ms": round(planner_ms, 3),
                "policy_ms": response.policy_ms,
                "scan_ms": response.scan_ms,
                "server_total_ms": response.server_total_ms,
                "end_to_end_ms": round(total_ms, 3),
            }


        except (LLMUnavailableError, PlanningError, OpenAIError, ValueError) as exc:
            row = {
                "run": index,
                "status": type(exc).__name__,
                "planner_ms": None,
                "policy_ms": None,
                "scan_ms": None,
                "server_total_ms": None,
                "end_to_end_ms": None,
            }

        rows.append(row)
        print(f"Run {index}: {row['status']}")

    fields = [
        "run",
        "status",
        "planner_ms",
        "policy_ms",
        "scan_ms",
        "server_total_ms",
        "end_to_end_ms",
    ]

    await asyncio.to_thread(write_results, output, fields, rows)

    print(f"\nSaved results to {output}")

    successful = [r for r in rows if r["status"] == "success"]

    for field in fields[2:]:
        values = [r[field] for r in successful if r[field] is not None]

        if values:
            print(
                f"{field}: mean={statistics.mean(values):.3f} ms, "
                f"std={statistics.stdev(values) if len(values) > 1 else 0:.3f} ms"
            )


if __name__ == "__main__":
    asyncio.run(main())
