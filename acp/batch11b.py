"""Batch 11b (batch 11 re-run after the YAML fix): summary.

Same success-within-k rows, per-try attribution and batch-9 comparison as batch 11 (acp.batch11),
plus what the addendum asks for: the ParserError count (expected 0) and every other error class of
the new tries, the pairs a budget stop left not run, the new spend, and the batch-11 (buggy) result
on the same pairs. Protocol: repeats/batch11/PROTOCOL.md + repeats/batch11b/PROTOCOL-ADDENDUM.md.
"""

from __future__ import annotations

import json
from pathlib import Path

from acp import batch11 as b11
from acp import bench_gate as g
from acp.repeats import wilson

GENERATOR = "python3 tools/batch11b_summary.py"
DIR = "repeats/batch11b"
ERROR_COLS = ("model", "pairs_planned", "pairs_run", "pairs_not_run", "new_tries", "parser_errors",
              "validation_errors", "other_errors", "cost_new_usd")
B11_COLS = ("model", "pairs", "b11_succeeded", "b11_parser_errors", "b11b_succeeded", "k")


def new_tries(r: dict) -> list[dict]:
    return [t for t in r.get("tries") or [] if not t.get("reused_from")]


def error_rows(recs: list[dict], planned: list[dict]) -> list[dict]:
    """Per model and pooled: pairs planned / run / not run (budget stop), error classes of the new
    tries (try 1 is reused from batch 11), new spend."""
    plan = dict(b11._groups(planned))
    out = []
    for model, rs in b11._groups(recs):
        ts = [t for r in rs for t in new_tries(r)]
        ec = [t.get("error_class") for t in ts]
        np = len(plan.get(model, []))
        out.append({"model": model, "pairs_planned": np, "pairs_run": len(rs), "pairs_not_run": np - len(rs),
                    "new_tries": len(ts), "parser_errors": ec.count("ParserError"),
                    "validation_errors": ec.count("ValidationException"),
                    "other_errors": sum(e not in (None, "ParserError", "ValidationException") for e in ec),
                    "cost_new_usd": round(sum(r.get("cost_new_usd", 0.0) for r in rs), 4)})
    return out


def b11_rows(recs: list[dict], old: list[dict]) -> list[dict]:
    """Batch 11 (rewrites broken by the YAML bug) against 11b on the pairs 11b ran."""
    base = {b11.pair(r): r for r in old}
    both = [r for r in recs if b11.pair(r) in base]
    K = b11.max_tries(recs)
    out = []
    for model, rs in b11._groups(both):
        o = [base[b11.pair(r)] for r in rs]
        out.append({"model": model, "pairs": len(rs),
                    "b11_succeeded": sum(r.get("success_at") is not None for r in o),
                    "b11_parser_errors": sum(t.get("error_class") == "ParserError" for r in o for t in r["tries"]),
                    "b11b_succeeded": sum(r.get("success_at") is not None for r in rs), "k": K})
    return out


def _ci(s: int, n: int) -> str:
    lo, hi = wilson(s, n)
    return f"{s}/{n} [{100 * lo:.1f}, {100 * hi:.1f}]"


def markdown(succ, tries, cmp, errs, old, K) -> str:
    md = b11.markdown(succ, tries, cmp, K).split("\n")
    md[0] = f"# Batch 11b seeded adaptive attacker after the YAML fix (gated arm, set A, up to {K} tries per pair)"
    md[2] = md[2].replace("`" + b11.GENERATOR + "`", "`" + GENERATOR + "`").replace(
        "Try 1 = ", "Try 1 = reused from the batch-11 record (no call), ")
    text = "\n".join(md).replace("batch 11 within K", "batch 11b within K").replace(
        "| batch 11 try 1 |", "| try 1 (reused) |").replace("(try 1 re-run", "(try 1")
    p = next((r for r in errs if r["model"] == "pooled"), None)
    out = [text.rstrip("\n"), "", "## Errors, budget stops and spend", "",
           "Error classes of the new tries only (try 1 is reused). ParserError must be 0 after the fix; "
           "ValidationException = Bedrock refused the victim's tool call (tool name outside "
           "`[a-zA-Z0-9_-]+`), a victim error as in batch 11, kept in n. Pairs not run were left by a "
           "budget stop and are not in n.", "",
           "| model | pairs planned | run | not run | new tries | ParserError | ValidationException | "
           "other errors | new spend $ |", "|---|---|---|---|---|---|---|---|---|"]
    for r in errs:
        out.append(f"| {r['model']} | {r['pairs_planned']} | {r['pairs_run']} | {r['pairs_not_run']} | "
                   f"{r['new_tries']} | {r['parser_errors']} | {r['validation_errors']} | {r['other_errors']} | "
                   f"{r['cost_new_usd']:.3f} |")
    out += ["", "## Against batch 11 (YAML bug) on the same pairs", "",
            "| model | pairs | batch 11 within K | batch 11 ParserError tries | batch 11b within K |",
            "|---|---|---|---|---|"]
    for r in old:
        out.append(f"| {r['model']} | {r['pairs']} | {_ci(r['b11_succeeded'], r['pairs'])} | "
                   f"{r['b11_parser_errors']} | {_ci(r['b11b_succeeded'], r['pairs'])} |")
    if p:
        out += ["", f"New spend ${p['cost_new_usd']:.3f}; ParserError {p['parser_errors']}; "
                f"pairs not run {p['pairs_not_run']}."]
    return "\n".join(out) + "\n"


def build(root: Path) -> dict:
    """All outputs of batch 11b as {relative path: text}, generated from the run records."""
    root = Path(root)
    recs = [r for r in g.load_records(root / DIR / "runs") if r.get("attack") == b11.ATTACK]
    old = [r for r in g.load_records(root / "repeats" / "batch11" / "runs") if r.get("attack") == b11.ATTACK]
    b9 = g.load_records(root / "repeats" / "batch9" / "runs")
    K = b11.max_tries(recs)
    succ, tries, cmp = b11.success_rows(recs), b11.try_rows(recs), b11.compare_rows(recs, b9)
    errs, olds = error_rows(recs, old), b11_rows(recs, old)
    summary = {"success": succ, "tries": tries, "compare": cmp, "comparison": b11.comparison_line(cmp),
               "errors": errs, "batch11": olds, "runs": len(recs), "max_tries": K,
               "n_tries": sum(r.get("n_tries", 1) for r in recs),
               "cost_usd": round(sum(r.get("cost_usd", 0.0) for r in recs), 4),
               "cost_new_usd": round(sum(r.get("cost_new_usd", 0.0) for r in recs), 4)}
    d = DIR + "/"
    return {
        d + "summary.json": json.dumps(summary, indent=1, sort_keys=True) + "\n",
        d + "summary.md": markdown(succ, tries, cmp, errs, olds, K),
        d + "success.csv": g.to_csv(succ, b11.SUCCESS_COLS),
        d + "tries.csv": g.to_csv(tries, b11.TRY_COLS),
        d + "compare.csv": g.to_csv(cmp, b11.COMPARE_COLS),
        d + "errors.csv": g.to_csv(errs, ERROR_COLS),
        d + "batch11.csv": g.to_csv(olds, B11_COLS),
    }
