"""Summarize raw experiment CSVs into tables and (optionally) a figure.

Never reports a number that was not computed from a raw CSV row produced by
``run_comparison.py`` / ``run_latency.py``; if a condition's CSV is missing or
empty, it is reported as "not available", not estimated or omitted silently.
"""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _read_rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def summarize_latency(rows: list[dict]) -> list[dict]:
    successful = [row for row in rows if row.get("status") == "success"]
    summary = []
    for field_name in ("planner_ms", "policy_ms", "scan_ms", "server_total_ms"):
        values = [float(row[field_name]) for row in successful if row.get(field_name)]
        if not values:
            summary.append({"phase": field_name, "n": 0, "mean_ms": None, "std_ms": None})
            continue
        summary.append(
            {
                "phase": field_name,
                "n": len(values),
                "mean_ms": round(statistics.mean(values), 3),
                "std_ms": round(statistics.stdev(values), 3) if len(values) > 1 else 0.0,
            }
        )
    return summary


def summarize_comparison(rows: list[dict]) -> list[dict]:
    """Block/true-bypass rate per condition, over every case not in benign_authorized.

    A "bypass" here means Nmap actually ran against a destination/port pair
    outside the known-authorized set for ``config/policy.example.yaml``
    (127.0.0.1:8080). A case whose malformed/injected content was simply
    neutralized into that same authorized plan is not a bypass; it is a
    successful rejection of the injected content.
    """
    authorized_target = "127.0.0.1"
    authorized_ports = {"8080"}

    by_condition: dict[str, list[dict]] = {}
    for row in rows:
        by_condition.setdefault(row["condition"], []).append(row)

    summary = []
    for condition, condition_rows in sorted(by_condition.items()):
        unauthorized = [row for row in condition_rows if row.get("category") != "benign_authorized"]
        if not unauthorized:
            summary.append(
                {"condition": condition, "n_unauthorized_cases": 0, "block_rate": None, "bypass_rate": None}
            )
            continue
        blocked = sum(
            1
            for row in unauthorized
            if row.get("status") in ("rejected", "parse_error") or row.get("nmap_started") == "False"
        )
        bypassed = sum(
            1
            for row in unauthorized
            if row.get("nmap_started") == "True"
            and row.get("status") == "success"
            and (
                row.get("destination") != authorized_target
                or not set((row.get("ports") or "").split(",")) <= authorized_ports
            )
        )
        summary.append(
            {
                "condition": condition,
                "n_unauthorized_cases": len(unauthorized),
                "block_rate": round(blocked / len(unauthorized), 3),
                "bypass_rate": round(bypassed / len(unauthorized), 3),
            }
        )
    return summary


def _print_table(title: str, rows: list[dict]) -> None:
    print(f"\n{title}")
    if not rows:
        print("  not available (no raw CSV rows found)")
        return
    headers = list(rows[0].keys())
    print("  " + " | ".join(headers))
    for row in rows:
        print("  " + " | ".join(str(row[header]) for header in headers))


def _write_csv(rows: list[dict], path: Path) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _write_figure(latency_summary: list[dict], path: Path) -> None:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print(
            "matplotlib is not installed; skipping the figure "
            "(install the 'eval' extra: pip install -e '.[eval]').",
            file=sys.stderr,
        )
        return

    plotted = [row for row in latency_summary if row["mean_ms"] is not None]
    if not plotted:
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots()
    ax.bar(
        [row["phase"] for row in plotted],
        [row["mean_ms"] for row in plotted],
        yerr=[row["std_ms"] for row in plotted],
    )
    ax.set_ylabel("mean latency (ms)")
    ax.set_title(f"Matched-run latency (n={plotted[0]['n']} successful runs)")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--latency-csv", type=Path, default=PROJECT_ROOT / "results" / "latency_raw.csv"
    )
    parser.add_argument(
        "--comparison-csv", type=Path, default=PROJECT_ROOT / "results" / "comparison_raw.csv"
    )
    parser.add_argument(
        "--output-dir", type=Path, default=PROJECT_ROOT / "results"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    latency_rows = _read_rows(args.latency_csv)
    comparison_rows = _read_rows(args.comparison_csv)

    latency_summary = summarize_latency(latency_rows)
    comparison_summary = summarize_comparison(comparison_rows)

    _print_table("Latency summary (ms)", latency_summary)
    _print_table("Comparison summary (block/bypass rate)", comparison_summary)

    _write_csv(latency_summary, args.output_dir / "latency_summary.csv")
    _write_csv(comparison_summary, args.output_dir / "comparison_summary.csv")
    _write_figure(latency_summary, args.output_dir / "latency_summary.png")


if __name__ == "__main__":
    main()
