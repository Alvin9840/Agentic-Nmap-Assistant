
"""Measure LLM -> MCP -> Policy Guard -> Nmap latency."""

import argparse
import asyncio
import csv
import statistics
import time
from pathlib import Path

from safe_nmap.agent.cli import create_server_parameters
from safe_nmap.agent.llm_planner import LLMPlanner
from safe_nmap.agent.mcp_client import MCPClient


REQUEST = "profile web-check port 8080 target 127.0.0.1"

FIELDS = [
    "run",
    "status",
    "planner_ms",
    "mcp_connect_ms",
    "mcp_tool_roundtrip_ms",
    "server_total_ms",
    "policy_phase_ms",
    "scan_ms",
    "end_to_end_ms",
    "nmap_started",
]


def ms(seconds):
    return round(seconds * 1000, 3)


async def measure(repeats, output):
    policy = Path("config/policy.example.yaml").resolve()

    if not policy.exists():
        raise FileNotFoundError(
            "Run this script from the project root."
        )

    planner = LLMPlanner(condition="C4")

    server_env = {
        "SAFE_NMAP_POLICY": str(policy),
        "SAFE_NMAP_AUDIT_LOG": str(
            Path("results/mcp_latency_audit.jsonl").resolve()
        ),
    }

    rows = []

    for index in range(1, repeats + 1):
        row = {field: "" for field in FIELDS}
        row["run"] = index

        total_start = time.perf_counter()

        try:
            start = time.perf_counter()

            request = await asyncio.to_thread(
                planner.plan_scan_request,
                REQUEST,
            )

            row["planner_ms"] = ms(
                time.perf_counter() - start
            )

            start = time.perf_counter()

            async with MCPClient(
                create_server_parameters(env=server_env)
            ) as client:

                row["mcp_connect_ms"] = ms(
                    time.perf_counter() - start
                )

                start = time.perf_counter()

                response = await client.scan_network(request)

                row["mcp_tool_roundtrip_ms"] = ms(
                    time.perf_counter() - start
                )

            row["status"] = response.status
            row["server_total_ms"] = response.server_total_ms
            row["policy_phase_ms"] = response.policy_ms
            row["scan_ms"] = response.scan_ms
            row["nmap_started"] = response.nmap_started

        except Exception as exc:
            row["status"] = f"ERROR:{type(exc).__name__}"
            print(f"Run {index}: {exc}")

        finally:
            row["end_to_end_ms"] = ms(
                time.perf_counter() - total_start
            )

            rows.append(row)

            print(
                f"Run {index}: {row['status']}, "
                f"total={row['end_to_end_ms']} ms"
            )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=FIELDS,
        )

        writer.writeheader()
        writer.writerows(rows)

    successful = [
        row for row in rows
        if row["status"] == "success"
        and row["nmap_started"] is True
    ]

    print(
        f"\nSaved {len(rows)} runs to {output}"
    )

    print(
        f"Successful scans: {len(successful)}"
    )

    if successful:
        metrics = [
            "planner_ms",
            "mcp_connect_ms",
            "mcp_tool_roundtrip_ms",
            "server_total_ms",
            "policy_phase_ms",
            "scan_ms",
            "end_to_end_ms",
        ]

        for field in metrics:
            values = [
                float(row[field])
                for row in successful
                if row[field] != ""
                and row[field] is not None
            ]

            if values:
                print(
                    f"{field}: "
                    f"{statistics.mean(values):.3f} ms"
                )

    if len(successful) != repeats:
        print(
            "WARNING: Some runs were unsuccessful. "
            "Do not treat all runs as successful-scan "
            "latency measurements."
        )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--repeats",
        type=int,
        default=10,
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path(
            "results/latency_mcp_e2e.csv"
        ),
    )

    args = parser.parse_args()

    if args.repeats < 1:
        parser.error("--repeats must be positive")

    asyncio.run(
        measure(args.repeats, args.output)
    )


if __name__ == "__main__":
    main()
