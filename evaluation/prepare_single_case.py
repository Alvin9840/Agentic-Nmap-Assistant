
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]

source = root / "evaluation" / "benign_cases.json"
output = root / "results" / "single_benign_case.json"

data = json.loads(source.read_text(encoding="utf-8"))

case = next(
    case for case in data["cases"]
    if case["case_id"] == "C-001"
)

output.parent.mkdir(parents=True, exist_ok=True)

output.write_text(
    json.dumps({"cases": [case]}, indent=2),
    encoding="utf-8",
)

print(f"Prepared: {case['case_id']}")
print(f"Saved: {output}")
