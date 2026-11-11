"""L26: per victim model and batch, the exact provider model id, run dates (UTC), runs, tool calls, tokens,
and wall-clock hours (sum of per-run ts_end - ts_start). Read from the run records only."""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from acp import bench_gate as g  # noqa: E402
from common import write_csv  # noqa: E402

BATCHES = ("batch6", "batch7", "batch8", "batch10", "batch11b", "batch14", "batch15")


def ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def main() -> None:
    rows = []
    for b in BATCHES:
        d = ROOT / "repeats" / b / "runs"
        if not d.exists():
            continue
        groups: dict[str, list[dict]] = {}
        for r in g.load_records(d):
            groups.setdefault(r["model"], []).append(r)
        for m, rs in sorted(groups.items()):
            ids = sorted({i for r in rs for i in (r.get("model_ids") or [])}) or [m]
            starts = [ts(r["ts_start"]) for r in rs if r.get("ts_start")]
            ends = [ts(r["ts_end"]) for r in rs if r.get("ts_end")]
            hours = sum((ts(r["ts_end"]) - ts(r["ts_start"])).total_seconds() for r in rs
                        if r.get("ts_start") and r.get("ts_end")) / 3600
            calls = sum(len(r.get("calls") or []) for r in rs)
            tok_in = sum(int((r.get("usage") or {}).get("input", 0) or 0) for r in rs)
            tok_out = sum(int((r.get("usage") or {}).get("output", 0) or 0) for r in rs)
            rows.append({"batch": b, "model": m, "model_ids": ";".join(ids), "runs": len(rs),
                         "tool_calls": calls, "tokens_in": tok_in, "tokens_out": tok_out,
                         "first_utc": min(starts).strftime("%Y-%m-%d") if starts else "",
                         "last_utc": max(ends).strftime("%Y-%m-%d") if ends else "",
                         "run_hours": round(hours, 2)})
    print(write_csv("run_inventory.csv", rows))
    for r in rows:
        print(r)


if __name__ == "__main__":
    main()
