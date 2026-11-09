
"""Matched policy-on/off benchmark for a fixed authorized scan plan.

This measures authorization plus command construction only.
It does not run Nmap or disable policy enforcement in production.
"""

import csv
import statistics
import time
from pathlib import Path

from safe_nmap.server.command_builder import build_nmap_command
from safe_nmap.server.policy_guard import authorize, get_policy
from safe_nmap.shared.schemas import ScanRequest

OUTPUT = Path("results/policy_overhead.csv")
REPEATS = 1000

POLICY_PATH = "config/policy.example.yaml"


def measure(action):
    start = time.perf_counter_ns()
    result = action()
    elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
    return elapsed_ms, result


def main():
    policy = get_policy(POLICY_PATH)

    request = ScanRequest(
        target="127.0.0.1",
        ports=[8080],
        profile="web-check",
    )

    # Obtain the fixed plan using the real Policy Guard first.
    fixed_plan = authorize(request, policy)

    assert fixed_plan.resolved_ip == "127.0.0.1"
    assert fixed_plan.ports == [8080]
    assert fixed_plan.profile == "web-check"

    expected_command = build_nmap_command(fixed_plan)

    def policy_on():
        plan = authorize(request, policy)
        return build_nmap_command(plan)

    def policy_off():
        # Reuse a previously authorized fixed plan.
        # No request parameters can be changed by the caller.
        return build_nmap_command(fixed_plan)

    # Warm up both paths.
    for _ in range(100):
        assert policy_on() == expected_command
        assert policy_off() == expected_command

    rows = []

    for index in range(1, REPEATS + 1):
        # Alternate execution order to reduce order bias.
        if index % 2:
            on_ms, on_command = measure(policy_on)
            off_ms, off_command = measure(policy_off)
        else:
            off_ms, off_command = measure(policy_off)
            on_ms, on_command = measure(policy_on)

        assert on_command == off_command == expected_command

        rows.append({
            "run": index,
            "policy_on_ms": round(on_ms, 6),
            "policy_off_ms": round(off_ms, 6),
            "overhead_ms": round(on_ms - off_ms, 6),
        })

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "run",
                "policy_on_ms",
                "policy_off_ms",
                "overhead_ms",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print("Runs:", len(rows))

    for field in ("policy_on_ms", "policy_off_ms", "overhead_ms"):
        values = [row[field] for row in rows]
        print(
            field,
            "mean=", round(statistics.mean(values), 6),
            "std=", round(statistics.stdev(values), 6),
            "median=", round(statistics.median(values), 6),
        )

    print("Saved:", OUTPUT)


if __name__ == "__main__":
    main()
