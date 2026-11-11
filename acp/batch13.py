"""Batch 13: sampled repeats of the Claude AgentDojo runs (repeats/batch13/PROTOCOL.md).

Rep 0 is batch 6 B1 (Claude models); reps 1-3 are batch 13, provider-default sampling. Stdlib only.
"""

from __future__ import annotations

import json
from pathlib import Path

from acp import bench_gate as g

GENERATOR = "python3 tools/batch13_summary.py"
MODELS = ("claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5")
ARMS = ("plain", "gated")
REPS = (1, 2, 3)
PLANNED = 77  # B1 runs per model, arm and rep
ISSUED = ("succeeded", "reached-target")
REPEAT_COLS = ("model", "arm", "rep") + g.CSV_COLS[3:] + ("not_run", "issued", "issued_rate", "issued_lo", "issued_hi")
COMPARE_COLS = ("model", "arm", "metric", "r0", "r1", "r2", "r3", "pooled", "pooled_lo", "pooled_hi",
                "r0_in_pooled_ci", "order_flip_reps", "conclusion_changes")


def label(r: dict) -> str:
    return f"{r['arm']}/r{r.get('rep', 0)}"


def records(root: Path) -> list[dict]:
    """Rep 0 (batch 6 B1, Claude) and reps 1-3 (batch 13), arm relabelled `<arm>/r<rep>`."""
    root = Path(root)
    b6 = [{**r, "rep": 0} for r in g.load_records(root / "repeats" / "batch6" / "runs")
          if r.get("set") == "B1" and r["model"] in MODELS]
    b13 = []
    for rep in REPS:
        d = root / "repeats" / "batch13" / "runs" / f"r{rep}"
        b13 += [{**r, "rep": rep} for r in g.load_records(d) if r.get("set") == "B1"] if d.is_dir() else []
    return [{**r, "arm": label(r), "base_arm": r["arm"]} for r in b6 + b13]


def _issued(recs: list[dict]) -> dict:
    att = [r for r in recs if r["kind"] == "attacked"]
    return g._rate(sum(g.classify(r) in ISSUED for r in att), len(att))


def summarize(recs: list[dict]) -> dict:
    pooled = [{**r, "arm": f"{r['base_arm']}/pooled"} for r in recs if r["rep"] in REPS]
    s = g.aggregate(recs + pooled)
    for row in s["rows"]:
        arm, rep = row["arm"].split("/")
        sub = [r for r in recs + pooled if r["model"] == row["model"] and r["arm"] == row["arm"]]
        row["issued_call"] = _issued(sub)
        row["not_run"] = PLANNED * (len(REPS) if rep == "pooled" else 1) - row["runs"]
    return s


def _row(s: dict, model: str, arm: str) -> dict | None:
    return next((r for r in s["rows"] if r["model"] == model and r["arm"] == arm), None)


def _sign(x: float) -> int:
    return (x > 0) - (x < 0)


def compare(s: dict) -> list[dict]:
    """Rep 0 vs reps 1-3 per model, arm and metric, with the two pre-registered change tests."""
    out = []
    for model in MODELS:
        flips = {}
        for metric in ("asr", "benign_utility"):
            r0p, r0g = _row(s, model, "plain/r0"), _row(s, model, "gated/r0")
            base = _sign(r0p[metric]["rate"] - r0g[metric]["rate"]) if r0p and r0g else 0
            fl = []
            for rep in REPS:
                p, q = _row(s, model, f"plain/r{rep}"), _row(s, model, f"gated/r{rep}")
                if p and q and p[metric]["n"] and q[metric]["n"]:
                    d = _sign(p[metric]["rate"] - q[metric]["rate"])
                    if base and d and d != base:
                        fl.append(f"r{rep}")
            flips[metric] = fl
        for arm in ARMS:
            for metric in ("asr", "issued_call", "benign_utility"):
                vals = {f"r{k}": (_row(s, model, f"{arm}/r{k}") or {}).get(metric) for k in (0,) + REPS}
                pool = (_row(s, model, f"{arm}/pooled") or {}).get(metric)
                r0 = vals["r0"]["rate"] if vals["r0"] else None
                inside = None
                if pool and pool["n"] and r0 is not None:
                    inside = pool["ci95"][0] <= r0 <= pool["ci95"][1]
                fl = flips.get(metric, [])
                tested = metric in flips
                out.append({
                    "model": model, "arm": arm, "metric": metric,
                    **{k: (v["rate"] if v else None) for k, v in vals.items()},
                    "pooled": pool["rate"] if pool else None,
                    "pooled_lo": pool["ci95"][0] if pool else None, "pooled_hi": pool["ci95"][1] if pool else None,
                    "r0_in_pooled_ci": inside,
                    "order_flip_reps": " ".join(fl) if tested else "",
                    "conclusion_changes": (bool(fl) or inside is False) if tested else None,
                })
    return out


def repeat_rows(s: dict) -> list[dict]:
    out = []
    for c, r in zip(g.csv_rows(s), s["rows"]):
        arm, rep = r["arm"].split("/")
        ic = r["issued_call"]
        out.append({**c, "arm": arm, "rep": rep, "not_run": r["not_run"], "issued": ic["k"],
                    "issued_rate": ic["rate"], "issued_lo": ic["ci95"][0], "issued_hi": ic["ci95"][1]})
    return out


def _md(s: dict, cmp: list[dict]) -> str:
    md = g.markdown(s, "Batch 13: Claude AgentDojo B1, rep 0 (batch 6) and sampled reps 1-3")
    md = md.replace("`python3 -m acp batch6-summary`", f"`{GENERATOR}`")
    out = [md, "Arm labels: `<arm>/r0` = batch 6 B1; `<arm>/r1..r3` = batch 13 repeats (provider-default "
           "sampling, `important_instructions`); `<arm>/pooled` = reps 1-3 together.", "",
           "Issued-call rate (succeeded + reached-target) and runs not made:", "",
           "| model | arm | issued-call | not run |", "|---|---|---|---|"]
    for r in s["rows"]:
        out.append(f"| {r['model']} | {r['arm']} | {g._pct(r['issued_call'])} | {r['not_run']} |")
    out += ["", "Rep 0 vs reps 1-3 (rates in %; a conclusion changes if the plain vs gated order flips in a rep, "
            "or rep 0 lies outside the pooled 95% Wilson interval; repeats/batch13/PROTOCOL.md):", "",
            "| model | arm | metric | r0 | r1 | r2 | r3 | pooled [95% CI] | r0 in CI | order flips | changes |",
            "|---|---|---|---|---|---|---|---|---|---|---|"]

    def pc(x):
        return "n/a" if x is None else f"{100 * x:.1f}"

    for c in cmp:
        yn = {True: "yes", False: "no", None: "-"}
        out.append(f"| {c['model']} | {c['arm']} | {c['metric']} | {pc(c['r0'])} | {pc(c['r1'])} | {pc(c['r2'])} | "
                   f"{pc(c['r3'])} | {pc(c['pooled'])} [{pc(c['pooled_lo'])}, {pc(c['pooled_hi'])}] | "
                   f"{yn[c['r0_in_pooled_ci']]} | {c['order_flip_reps'] or '-'} | {yn[c['conclusion_changes']]} |")
    return "\n".join(out) + "\n"


def build(root: Path) -> dict:
    """All outputs of batch 13 as {relative path: text}, generated from the run records."""
    s = summarize(records(root))
    cmp = compare(s)
    return {
        "repeats/batch13/summary.json": json.dumps({"repeats": s, "compare": cmp}, indent=1, sort_keys=True) + "\n",
        "repeats/batch13/summary.md": _md(s, cmp),
        "repeats/batch13/repeats.csv": g.to_csv(repeat_rows(s), REPEAT_COLS),
        "repeats/batch13/compare.csv": g.to_csv(cmp, COMPARE_COLS),
    }
