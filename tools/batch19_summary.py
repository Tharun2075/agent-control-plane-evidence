"""Batch-19 summary (repeats/batch19/PROTOCOL.md): Progent arm vs batch-7 gated and plain.

`python tools/batch19_summary.py [--dir runs|pilot]` reads `repeats/batch19/<dir>/*__progent__B1.jsonl`
and the batch-7 B1 files, and writes `repeats/batch19/<dir>-summary.{md,json}`.
"Broken" normal tasks are benign tasks the plain (no defence) arm solved and the defended arm failed.
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "repeats"
MODELS = ["openai.gpt-oss-20b-1:0", "openai.gpt-oss-120b-1:0", "qwen.qwen3-32b-v1:0",
          "qwen.qwen3-vl-235b-a22b", "mistral.mistral-large-3-675b-instruct", "deepseek.v3.2"]
N_BENIGN, N_ATTACKED, B, SEED = 37, 40, 2000, 19


def wilson(k: int, n: int) -> list:
    # same formula as tools/batch17_summary.py
    import math
    if n == 0:
        return [None, None]
    z, p = 1.959964, k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def cluster_ci(rows: list, val) -> list:
    """Task-clustered bootstrap 95% interval: resample (suite, user task) clusters."""
    cl = {}
    for r in rows:
        cl.setdefault((r["suite"], r["ut"]), []).append(val(r))
    keys = list(cl)
    if not keys:
        return [None, None]
    rng, stats = random.Random(SEED), []
    for _ in range(B):
        pick = [x for k in rng.choices(keys, k=len(keys)) for x in cl[k]]
        stats.append(sum(pick) / len(pick))
    stats.sort()
    return [round(stats[int(0.025 * B)], 4), round(stats[int(0.975 * B) - 1], 4)]


def load(path: Path) -> list:
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


def key(r: dict) -> tuple:
    return (r["suite"], r["ut"], r.get("it"))


def stats(rows: list, plain: list | None = None) -> dict:
    ben = [r for r in rows if r["kind"] == "benign"]
    att = [r for r in rows if r["kind"] == "attacked"]
    asr = sum(bool(r.get("security")) for r in att)
    ut = sum(bool(r.get("utility")) for r in ben)
    out = {"runs": len(rows), "benign": len(ben), "attacked": len(att),
           "errors": sum(bool(r.get("error_class")) for r in rows),
           "benign_utility": ut, "benign_utility_ci": wilson(ut, len(ben)),
           "asr": asr, "asr_ci": wilson(asr, len(att)),
           "utility_under_attack": sum(bool(r.get("utility")) for r in att),
           "target_attempted": sum(bool(r.get("target_call_attempted")) for r in att),
           "checks_reached": sum((r.get("gate_checks") or 0) > 0 for r in att),
           "target_blocked": sum((r.get("blocked_target") or 0) > 0 for r in att),
           "blocks_benign": sum((r.get("gate_blocks") or 0) > 0 for r in ben),
           "cost_usd": round(sum(r.get("cost_usd") or 0.0 for r in rows), 4)}
    if plain is not None:
        solved = {key(r) for r in plain if r["kind"] == "benign" and r.get("utility")}
        out["broken"] = sum(1 for r in ben if key(r) in solved and not r.get("utility"))
        out["plain_solved_here"] = sum(1 for r in ben if key(r) in solved)
    return out


def pct(k, n):
    return "-" if not n else f"{100 * k / n:.0f}%"


def build(sub: str) -> dict:
    res = {"dir": sub, "models": {}, "pooled": {}}
    pooled = {"progent": [], "gated": []}
    for m in MODELS:
        f = m.replace(":", "_")
        pro = load(ROOT / "batch19" / sub / f"{f}__progent__B1.jsonl")
        if not pro:
            continue
        keys = {key(r) for r in pro}
        gated = load(ROOT / "batch7" / "runs" / f"{f}__gated__B1.jsonl")
        plain = load(ROOT / "batch7" / "runs" / f"{f}__plain__B1.jsonl")
        if sub != "runs":  # pilot: compare on the same jobs only
            gated = [r for r in gated if key(r) in keys]
            plain = [r for r in plain if key(r) in keys]
        res["models"][m] = {"progent": stats(pro, plain), "gated": stats(gated, plain), "plain": stats(plain)}
        pooled["progent"] += pro
        pooled["gated"] += gated
    for arm, rows in pooled.items():
        s = stats(rows)
        s["asr_cluster_ci"] = cluster_ci([r for r in rows if r["kind"] == "attacked"], lambda r: bool(r.get("security")))
        s["benign_utility_cluster_ci"] = cluster_ci([r for r in rows if r["kind"] == "benign"], lambda r: bool(r.get("utility")))
        res["pooled"][arm] = s
    return res


def markdown(res: dict) -> str:
    L = [f"# Batch 19 summary ({res['dir']})", "",
         "Owner table: share of attacks stopped (1 - ASR) and normal tasks broken (solved without a defence,",
         "failed with it). Gated and plain are batch 7, on the same jobs.", "",
         "| model | Progent stopped | gate stopped | Progent broke | gate broke | Progent errors | Progent cost $ |",
         "|---|---|---|---|---|---|---|"]
    for m, d in res["models"].items():
        p, g = d["progent"], d["gated"]
        L.append(f"| {m} | {pct(p['attacked'] - p['asr'], p['attacked'])} ({p['attacked'] - p['asr']}/{p['attacked']}) | "
                 f"{pct(g['attacked'] - g['asr'], g['attacked'])} ({g['attacked'] - g['asr']}/{g['attacked']}) | "
                 f"{p['broken']}/{p['plain_solved_here']} | {g['broken']}/{g['plain_solved_here']} | {p['errors']} | {p['cost_usd']:.3f} |")
    L += ["", "Detail (Wilson 95%). Funnel on attacked runs: target attempted / checks reached / target blocked.", "",
          "| model | arm | runs | benign utility | ASR | utility under attack | funnel | errors | cost $ |",
          "|---|---|---|---|---|---|---|---|---|"]

    def row(name, arm, s):
        bu, a = s["benign_utility_ci"], s["asr_ci"]
        return (f"| {name} | {arm} | {s['runs']} | {s['benign_utility']}/{s['benign']} {bu} | {s['asr']}/{s['attacked']} {a} | "
                f"{s['utility_under_attack']}/{s['attacked']} | {s['target_attempted']}/{s['checks_reached']}/{s['target_blocked']} | "
                f"{s['errors']} | {s['cost_usd']:.3f} |")
    for m, d in res["models"].items():
        for arm in ("progent", "gated", "plain"):
            L.append(row(m, arm, d[arm]))
    for arm, s in res["pooled"].items():
        L.append(row("POOLED", arm, s))
    L += ["", "Pooled task-clustered bootstrap 95% (2000 resamples, seed 19):"]
    for arm, s in res["pooled"].items():
        L.append(f"- {arm}: ASR {s['asr_cluster_ci']}, benign utility {s['benign_utility_cluster_ci']}")
    return "\n".join(L) + "\n"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--dir", default="runs", choices=["runs", "pilot"])
    a = p.parse_args()
    res = build(a.dir)
    if not res["models"]:
        print(f"no batch19/{a.dir} files")
        return 1
    (ROOT / "batch19" / f"{a.dir}-summary.json").write_text(json.dumps(res, indent=1) + "\n")
    md = markdown(res)
    (ROOT / "batch19" / f"{a.dir}-summary.md").write_text(md)
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
