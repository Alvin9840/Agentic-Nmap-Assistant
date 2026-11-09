
"""Execute eligible C2/C3 plans against the authorized local lab only."""

import asyncio
import csv
import ipaddress
from collections import Counter
from pathlib import Path

from safe_nmap.server import parser, scanner

SOURCE = Path("results/execution_eligibility.csv")
OUTPUT = Path("results/contained_execution.csv")

ALLOWED_TARGET = "127.0.0.1"
ALLOWED_PORT = 8080

FIELDS = [
    "case_id",
    "condition",
    "eligibility",
    "execution_status",
    "nmap_started",
    "findings",
    "error",
]


async def evaluate(row):
    record = {
        "case_id": row["case_id"],
        "condition": row["condition"],
        "eligibility": row["eligibility"],
        "execution_status": "not_executed",
        "nmap_started": False,
        "findings": "",
        "error": "",
    }

    if row["eligibility"] != "eligible":
        record["execution_status"] = row["eligibility"]
        return record

    # Independently enforce the lab boundary before execution.
    try:
        target = str(ipaddress.IPv4Address(row["target"]))
    except ipaddress.AddressValueError:
        record["execution_status"] = "outside_lab_scope"
        return record

    if (
        target != ALLOWED_TARGET
        or row["ports"] != str(ALLOWED_PORT)
    ):
        record["execution_status"] = "outside_lab_scope"
        return record

    # Fixed command: LLM output cannot supply Nmap flags.
    command = [
        "nmap",
        "-n",
        "-sT",
        "-T3",
        "-oX",
        "-",
        "-p",
        str(ALLOWED_PORT),
        ALLOWED_TARGET,
    ]

    execution = await scanner.run_nmap(
        command,
        timeout_seconds=30,
    )

    record["nmap_started"] = execution.nmap_started

    if execution.error_message:
        record["execution_status"] = "scan_failed"
        record["error"] = execution.error_message
        return record

    if execution.xml_output is None:
        record["execution_status"] = "scan_failed"
        record["error"] = "No XML output"
        return record

    try:
        findings = parser.parse_nmap_xml(execution.xml_output)
    except parser.NmapParseError as exc:
        record["execution_status"] = "parse_error"
        record["error"] = str(exc)
        return record

    record["execution_status"] = "success"
    record["findings"] = ",".join(
        f"{finding.port}/{finding.state}"
        for finding in findings
    )
    return record


def read_rows():
    with SOURCE.open(newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


async def main():
    rows = await asyncio.to_thread(read_rows)

    records = []

    for row in rows:
        if row["condition"] not in ("C2", "C3"):
            continue

        result = await evaluate(row)
        records.append(result)

        print(
            result["condition"],
            result["case_id"],
            result["execution_status"],
            result["findings"],
        )

    def write_results():
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)

        with OUTPUT.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(records)

    await asyncio.to_thread(write_results)

    for condition in ("C2", "C3"):
        counts = Counter(
            record["execution_status"]
            for record in records
            if record["condition"] == condition
        )
        print(f"\n{condition}: {dict(counts)}")

    print(f"\nSaved {len(records)} rows to {OUTPUT}")


if __name__ == "__main__":
    asyncio.run(main())
