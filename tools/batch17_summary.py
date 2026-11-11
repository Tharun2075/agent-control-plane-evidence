"""Batch-17 summary (repeats/batch17/PROTOCOL.md): runs.csv + summary.{md,json} per sub-batch.

`python tools/batch17_summary.py` reads the main-run JSONL files and writes the three outputs per sub;
`--check` recomputes summary.json from runs.csv alone and fails on any difference.
"""
from __future__ import annotations

import csv
import json
import math
import sys
from collections import OrderedDict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "repeats" / "batch17"
SUBS = ("p1", "p2", "p3")
EXPECTED = {"p1": 88, "p2": 72, "p3": 100}
COLS = ["sub", "model", "arm", "kind", "suite", "ut", "it", "rep", "job_key", "security", "utility",
        "error_class", "dirty", "cost_usd", "victim_cost_usd", "reviewer_cost_usd", "in_tok", "out_tok",
        "rev_in_tok", "rev_out_tok", "converse_calls", "reviewer_calls", "gate_checks", "gate_blocks",
        "ts_start", "ts_end", "inj_calls", "inj_approve", "inj_parse_fail", "inj_scripted_approve",
        "ben_calls", "ben_approve", "ben_parse_fail", "ben_scripted_approve"]


def wilson(k: int, n: int) -> list:
    if n == 0:
        return [None, None]
    z, p = 1.959964, k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def row_of(r: dict) -> dict:
    u = r.get("usage") or {}
    ru = r.get("reviewer_usage") or {}
    out = {c: "" for c in COLS}
    out.update(sub=r["sub"], model=r["model"], arm=r["arm"], kind=r["kind"], suite=r["suite"], ut=r["ut"],
               it=r.get("it") or "", rep=r.get("rep", 1), job_key=r["job_key"],
               security="" if r.get("security") is None else int(bool(r["security"])),
               utility=int(bool(r.get("utility"))), error_class=r.get("error_class") or "",
               dirty=int(bool(r.get("dirty"))), cost_usd=r.get("cost_usd") or 0.0,
               victim_cost_usd=r.get("victim_cost_usd", r.get("cost_usd") or 0.0),
               reviewer_cost_usd=r.get("reviewer_cost_usd") or 0.0,
               in_tok=u.get("input", 0), out_tok=u.get("output", 0),
               rev_in_tok=ru.get("input", 0), rev_out_tok=ru.get("output", 0),
               converse_calls=len(r.get("stop_reasons") or []),
               gate_checks=r.get("gate_checks") or 0, gate_blocks=r.get("gate_blocks") or 0,
               ts_start=r.get("ts_start", ""), ts_end=r.get("ts_end", ""))
    rc = 0
    cnt = {k: 0 for k in COLS if k.startswith(("inj_", "ben_"))}
    for c in r.get("calls") or []:
        chk = c.get("chk")
        if not chk or "llm" not in chk:
            continue
        rc += 1
        pre = "inj_" if (r["kind"] == "attacked" and c.get("hit")) else ("ben_" if r["kind"] == "benign" else None)
        if pre is None:
            continue
        cnt[pre + "calls"] += 1
        cnt[pre + "approve"] += chk["llm"] == "APPROVE"
        cnt[pre + "parse_fail"] += chk["llm"] not in ("APPROVE", "DENY") or bool(chk.get("llm_error"))
        cnt[pre + "scripted_approve"] += bool((chk.get("scripted") or {}).get("ok"))
    if r["sub"] == "p1":
        out.update(cnt, reviewer_calls=rc)
    return out


def load_runs() -> list[dict]:
    rows = []
    for sub in SUBS:
        latest: "OrderedDict[tuple, dict]" = OrderedDict()
        for f in sorted((ROOT / sub / "runs").glob("*.jsonl")):
            for line in f.read_text().splitlines():
                if line.strip():
                    r = json.loads(line)
                    latest[(r["model"], r["arm"], r["job_key"])] = r  # resume: last record per job wins
        rows += [row_of(r) for r in latest.values()]
    return rows


def _f(x) -> float:
    return float(x) if x not in ("", None) else 0.0


def prop(k: int, n: int) -> dict:
    return {"k": k, "n": n, "rate": round(k / n, 4) if n else None, "ci95": wilson(k, n)}


def summarise(rows: list[dict]) -> dict:
    out = {}
    for sub in SUBS:
        groups: "OrderedDict[tuple, list]" = OrderedDict()
        for r in rows:
            if r["sub"] == sub:
                groups.setdefault((r["model"], r["arm"]), []).append(r)
        res = []
        for (model, arm), g in sorted(groups.items()):
            att = [r for r in g if r["kind"] == "attacked"]
            ben = [r for r in g if r["kind"] == "benign"]
            ts = sorted(t for r in g for t in (r["ts_start"], r["ts_end"]) if t)
            wall = ((datetime.fromisoformat(ts[-1].rstrip("Z")) - datetime.fromisoformat(ts[0].rstrip("Z")))
                    .total_seconds() if ts else 0.0)
            s = {"model": model, "arm": arm, "n": len(g), "expected": EXPECTED[sub] if sub != "p2" else 72,
                 "attacked": len(att), "benign": len(ben),
                 "errors": sum(1 for r in g if r["error_class"]),
                 "dirty_runs": sum(int(_f(r["dirty"])) for r in g),
                 "asr": prop(sum(int(_f(r["security"])) for r in att), len(att)),
                 "utility_benign": prop(sum(int(_f(r["utility"])) for r in ben), len(ben)),
                 "utility_attacked": prop(sum(int(_f(r["utility"])) for r in att), len(att)),
                 "converse_calls": sum(int(_f(r["converse_calls"])) for r in g),
                 "reviewer_calls": sum(int(_f(r["reviewer_calls"])) for r in g),
                 "tokens_in": sum(int(_f(r["in_tok"])) + int(_f(r["rev_in_tok"])) for r in g),
                 "tokens_out": sum(int(_f(r["out_tok"])) + int(_f(r["rev_out_tok"])) for r in g),
                 "cost_usd": round(sum(_f(r["cost_usd"]) for r in g), 4),
                 "reviewer_cost_usd": round(sum(_f(r["reviewer_cost_usd"]) for r in g), 4),
                 "wall_s": round(wall, 1)}
            if sub == "p1":
                for pre, name in (("inj_", "injected_calls"), ("ben_", "benign_calls")):
                    n = sum(int(_f(r[pre + "calls"])) for r in g)
                    a = sum(int(_f(r[pre + "approve"])) for r in g)
                    s[name] = {"n": n, "approve": prop(a, n), "deny": n - a,
                               "parse_fail_or_error": sum(int(_f(r[pre + "parse_fail"])) for r in g),
                               "scripted_would_approve": sum(int(_f(r[pre + "scripted_approve"])) for r in g)}
            res.append(s)
        out[sub] = res
    return out


def ci(p: dict) -> str:
    if not p["n"]:
        return "n/a"
    return f"{p['k']}/{p['n']} = {p['rate']:.3f} [{p['ci95'][0]:.3f}, {p['ci95'][1]:.3f}]"


def md(sub: str, res: list) -> str:
    L = [f"# Batch 17 {sub} summary (protocol: repeats/batch17/PROTOCOL.md; recompute: tools/batch17_summary.py --check)", ""]
    for s in res:
        L += [f"## {s['model']} / {s['arm']}",
              f"- runs {s['n']} of {s['expected']} planned (attacked {s['attacked']}, benign {s['benign']}); "
              f"errors {s['errors']}; dirty {s['dirty_runs']}",
              f"- ASR {ci(s['asr'])}", f"- utility benign {ci(s['utility_benign'])}",
              f"- utility attacked {ci(s['utility_attacked'])}"]
        if "injected_calls" in s:
            for k in ("injected_calls", "benign_calls"):
                c = s[k]
                L.append(f"- reviewer on {k.replace('_', ' ')}: approve {ci(c['approve'])}, deny {c['deny']}, "
                         f"parse fail/error {c['parse_fail_or_error']}, scripted would approve {c['scripted_would_approve']}")
        L += [f"- calls: converse {s['converse_calls']}, reviewer {s['reviewer_calls']}; tokens in {s['tokens_in']} "
              f"out {s['tokens_out']}; cost USD {s['cost_usd']:.4f} (reviewer {s['reviewer_cost_usd']:.4f}) "
              f"at list price; wall {s['wall_s']:.0f} s", ""]
    return "\n".join(L)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--check" in argv:
        bad = 0
        for sub in SUBS:
            csvp, js = ROOT / sub / "runs.csv", ROOT / sub / "summary.json"
            if not csvp.exists():
                print(f"{sub}: no runs.csv yet, skipped")
                continue
            with csvp.open() as fh:
                rows = list(csv.DictReader(fh))
            got = summarise(rows)[sub]
            want = json.loads(js.read_text())
            ok = got == want
            bad += not ok
            print(f"{sub}: summary.json {'matches' if ok else 'DIFFERS FROM'} a fresh recompute of runs.csv")
        return 1 if bad else 0
    rows = load_runs()
    allres = summarise(rows)
    for sub in SUBS:
        sr = [r for r in rows if r["sub"] == sub]
        if not sr:
            continue
        with (ROOT / sub / "runs.csv").open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=COLS)
            w.writeheader()
            w.writerows(sr)
        # summary.json is the recompute from the csv text, so --check compares like with like
        with (ROOT / sub / "runs.csv").open() as fh:
            res = summarise(list(csv.DictReader(fh)))[sub]
        (ROOT / sub / "summary.json").write_text(json.dumps(res, indent=1) + "\n")
        (ROOT / sub / "summary.md").write_text(md(sub, res))
        print(f"{sub}: {len(sr)} runs -> runs.csv, summary.json, summary.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
