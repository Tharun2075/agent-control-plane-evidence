"""Check that repeats/batch6/b1.csv and b2.csv agree with summary.json, cell by cell."""
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from acp.bench_gate import CSV_COLS, csv_rows  # noqa: E402


def main() -> int:
    b6 = ROOT / "repeats" / "batch6"
    summary = json.loads((b6 / "summary.json").read_text())
    bad = 0
    for part in ("B1", "B2"):
        want = [{c: ("" if r[c] is None else str(r[c])) for c in CSV_COLS} for r in csv_rows(summary[part])]
        with open(b6 / f"{part.lower()}.csv", newline="") as f:
            got = list(csv.DictReader(f))
        if got != want:
            bad += 1
            print(f"{part.lower()}.csv differs from summary.json[{part}]")
        runs = sum(r["runs"] for r in summary[part]["rows"])
        if runs != summary[part]["runs"]:
            bad += 1
            print(f"{part}: row runs {runs} != total {summary[part]['runs']}")
    print("batch6 CSV/JSON check:", "FAIL" if bad else "ok")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
