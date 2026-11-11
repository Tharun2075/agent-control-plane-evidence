"""Batch 15 (gpt-oss-120b B1 plain + gated after the empty-key toolUse.input fix): summary.

Same aggregation, outcome classes and Wilson intervals as batches 6-14 (acp.bench_gate). This module
puts the batch 15 runs next to the earlier gpt-oss-120b B1 cells (batch 7 = published v1.2, batch 14 at
the paper-fix12 gate), counts errors by class, and adds the errors-excluded ASR as a sensitivity line.
Protocol: repeats/batch15/PROTOCOL.md.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from acp import bench_gate as g
from acp.batch14 import _load, _table, relabel

GENERATOR = "python3 tools/batch15_summary.py"
MODEL = "openai.gpt-oss-120b-1:0"
STEM = "openai.gpt-oss-120b-1_0"
ERR_COLS = ("model", "arm", "runs", "errors", "provider_refused", "error_classes", "toolUse_input_errors")
SENS_COLS = ("model", "arm", "attacked", "attacked_errors", "asr", "asr_errors_excluded")


def _md(summary: dict, title: str) -> str:
    return g.markdown(summary, title).replace("`python3 -m acp batch6-summary`", f"`{GENERATOR}`")


def earlier(root: Path) -> list[dict]:
    """gpt-oss-120b B1: batch 7 plain + gated (published v1.2) and batch 14 gated."""
    rep = Path(root) / "repeats"
    recs = relabel([r for a in ("plain", "gated") for r in _load(rep / "batch7" / "runs" / f"{STEM}__{a}__B1.jsonl")],
                   lambda r: f"v1.2-{r['arm']}")
    return recs + relabel(_load(rep / "batch14" / "runs" / f"{STEM}__gated__B1.jsonl"), lambda r: f"b14-{r['arm']}")


def _fmt(k: int, n: int) -> str:
    return g._pct({"k": k, "n": n, "rate": k / n if n else None, "ci95": g.wilson(k, n)})


def error_rows(records: list[dict]) -> list[dict]:
    groups: dict[str, list[dict]] = {}
    for r in records:
        groups.setdefault(r["arm"], []).append(r)
    out = []
    for arm, rs in sorted(groups.items()):
        cls = Counter(r.get("error_class") for r in rs if g.classify(r) == "error")
        out.append({"model": MODEL, "arm": arm, "runs": len(rs),
                    "errors": sum(g.classify(r) == "error" for r in rs),
                    "provider_refused": sum(g.classify(r) == "provider-refused" for r in rs),
                    "error_classes": ";".join(f"{k}={v}" for k, v in sorted(cls.items(), key=lambda kv: str(kv[0]))),
                    "toolUse_input_errors": sum("toolUse.input is invalid" in (r.get("error") or "") for r in rs)})
    return out


def sensitivity_rows(records: list[dict]) -> list[dict]:
    """ASR with errored attacked runs dropped from the denominator (sensitivity only; headline keeps them)."""
    groups: dict[str, list[dict]] = {}
    for r in records:
        if r["kind"] == "attacked":
            groups.setdefault(r["arm"], []).append(r)
    out = []
    for arm, rs in sorted(groups.items()):
        k = sum(g.classify(r) == "succeeded" for r in rs)
        e = sum(g.classify(r) in ("error", "provider-refused") for r in rs)
        out.append({"model": MODEL, "arm": arm, "attacked": len(rs), "attacked_errors": e,
                    "asr": _fmt(k, len(rs)), "asr_errors_excluded": _fmt(k, len(rs) - e)})
    return out


def build(root: Path) -> dict:
    """All outputs of batch 15 as {relative path: text}, generated from the run records."""
    root = Path(root)
    b15 = relabel(g.load_records(root / "repeats" / "batch15" / "runs"), lambda r: f"b15-{r['arm']}")
    recs = earlier(root) + b15
    asr = g.aggregate(recs)
    err = error_rows(recs)
    sens = sensitivity_rows(recs)
    cost = round(sum(r.get("cost_usd", 0.0) for r in b15), 4)
    summary = {"asr": asr, "errors": err, "sensitivity_errors_excluded": sens, "runs": len(b15), "cost_usd": cost}
    d = "repeats/batch15/"
    md = "\n".join([
        _md(asr, "Batch 15 gpt-oss-120b B1 (AgentDojo 0.1.35, important_instructions) after the empty-key "
                 "toolUse.input fix vs batch 14 and published v1.2"),
        "## Errors by class (toolUse_input_errors = Bedrock ValidationException on toolUse.input)", "",
        *_table(err, ERR_COLS), "",
        "## Sensitivity: ASR with errored attacked runs excluded (headline rates above keep them)", "",
        *_table(sens, SENS_COLS), "",
        f"Batch 15 list-price cost (USD): {cost:.4f}", ""])
    return {
        d + "summary.json": json.dumps(summary, indent=1, sort_keys=True) + "\n",
        d + "summary.md": md,
        d + "summary.csv": g.to_csv(g.csv_rows(asr)),
        d + "errors.csv": g.to_csv(err, ERR_COLS),
        d + "sensitivity.csv": g.to_csv(sens, SENS_COLS),
    }
