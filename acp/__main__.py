"""CLI: python3 -m acp {reproduce,model-run,repeat,repeats-summary,mcp-check,verify-all,metrics,verify,summary,digest,validate}"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import manifest as mf
from . import metrics, summary
from .log import verify
from .runs import RUNS

ROOT = Path(__file__).resolve().parent.parent


def write_summary(log_path: Path) -> dict:
    s = summary.summarize(log_path)
    (log_path.parent / "summary.json").write_text(json.dumps(s, indent=2, sort_keys=True) + "\n")
    (log_path.parent / "summary.md").write_text(summary.to_markdown(s))
    return s


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="acp")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("reproduce", help="re-run all three reference tasks, write summaries and metrics")
    p = sub.add_parser("model-run", help="run model-driven task 4, 5 or 6 live (needs the model client)")
    p.add_argument("n", choices=["4", "5", "6"])
    sub.add_parser("verify-all", help="verify every committed run log (scripted and model-driven)")
    p = sub.add_parser("metrics", help="recompute metrics.json / metrics.md from runs/")
    p.add_argument("--out", help="write metrics JSON to this path instead (committed files untouched)")
    p = sub.add_parser("repeat", help="repeat model-driven run 4, 5 or 6 n times (repeats/PROTOCOL.md)")
    p.add_argument("--scenario", action="append", choices=["4", "5", "6", "7", "8", "9"],
                   help="repeatable; required for batch 1, default 4 5 6 with --model; 7 8 are batch 3, 9 is batch 4")
    p.add_argument("--n", type=int, default=10)
    p.add_argument("--out", help="default repeats/<scenario>")
    p.add_argument("--model", action="append",
                   help="batch 2: exact model id, optionally id:N (default N from the pre-registered plan); repeatable")
    p.add_argument("--jobs", type=int, default=1, help="batch 2: runs in parallel")
    p.add_argument("--budget", type=float, default=None, help="batch 2: stop launching at this summed cost (USD)")
    p.add_argument("--k-max", type=int, default=None, help="batch 2: only repetitions 1..k (smoke runs)")
    p.add_argument("--key-cmd", help="batch 2: command that prints the API key; read in this process only")
    p = sub.add_parser("repeats-summary", help="aggregate repeats/ into repeats/summary.json + summary.md")
    p.add_argument("--out", help="write the summary JSON to this path instead (committed files untouched)")
    p = sub.add_parser("batch6-summary", help="aggregate repeats/batch6/runs into summary.{md,json} and CSVs")
    p.add_argument("--out", help="write the files under this directory instead (committed files untouched)")
    sub.add_parser("mcp-check", help="repeat the MCP provenance check on five public URLs (repeats/mcp/)")
    p = sub.add_parser("verify", help="verify a hash-chained log")
    p.add_argument("log")
    p = sub.add_parser("summary", help="write summary.md/json next to a log")
    p.add_argument("log")
    p = sub.add_parser("digest", help="SHA-256 digest of a manifest")
    p.add_argument("manifest")
    p = sub.add_parser("validate", help="check a manifest has all six parts")
    p.add_argument("manifest")
    a = ap.parse_args(argv)

    if a.cmd == "reproduce":
        for n, fn in RUNS.items():
            out = ROOT / "runs" / n
            fn(ROOT, out)
            s = write_summary(out / "log.jsonl")
            print(f"run {n}: {s['steps']} records, verified={s['log_verified']}")
        m = metrics.write(ROOT)
        t = m["baseline"]["totals"]
        print(f"metrics: {t['steps']} steps, gated share {t['approval_gated_share_of_steps']}, "
              f"unclear {t['lawful_basis_unclear_steps']}, tamper {t['tamper_cases_detected']}/{t['tamper_cases_total']}")
        return 0 if t["all_verify_ok"] and t["tamper_cases_detected"] == t["tamper_cases_total"] else 1
    if a.cmd == "model-run":
        from .model_runs import MODEL_RUNS
        out = ROOT / "runs" / a.n
        MODEL_RUNS[a.n](ROOT, out)
        s = write_summary(out / "log.jsonl")
        print(f"run {a.n}: {s['steps']} records, verified={s['log_verified']}")
        return 0 if s["log_verified"] else 1
    if a.cmd == "verify-all":
        bad = 0
        logs = sorted((ROOT / "runs").glob("*/log.jsonl")) + sorted(
            [p for p in (ROOT / "repeats").glob("*/*/log.jsonl") if p.parent.name.isdigit()],
            key=lambda p: (p.parent.parent.name, int(p.parent.name))) + sorted(
            (ROOT / "repeats").glob("batch*/probe-*/log.jsonl")) + sorted(
            [p for b in ("batch2", "batch3", "batch4") for p in (ROOT / "repeats" / b).glob("*/*/*/log.jsonl")],
            key=lambda p: (p.parent.parent.parent.parent.name, p.parent.parent.parent.name, p.parent.parent.name,
                           int(p.parent.name))) + sorted((ROOT / "repeats" / "batch6" / "logs").glob("*.jsonl"))
        for log in logs:
            r = verify(log)
            bad += not r.ok
            print(f"{log.parent.relative_to(ROOT)}: {'ok' if r.ok else 'FAIL'} {r.records} records" +
                  ("" if r.ok else " " + "; ".join(r.errors[:3])))
        return 1 if bad else 0
    if a.cmd == "batch6-summary":
        from . import bench_gate
        base = Path(a.out) if a.out else ROOT
        for rel, text in bench_gate.build(ROOT).items():
            (base / rel).parent.mkdir(parents=True, exist_ok=True)
            (base / rel).write_text(text)
        return 0
    if a.cmd == "metrics":
        if a.out:
            Path(a.out).write_text(json.dumps(metrics.compute(ROOT), indent=2, sort_keys=True) + "\n")
        else:
            metrics.write(ROOT)
        return 0
    if a.cmd in ("repeat", "repeats-summary", "mcp-check"):
        from . import repeats
        if a.cmd == "repeat" and a.model:
            import shlex
            import subprocess
            scen = a.scenario or ["4", "5", "6"]
            batch = 4 if set(scen) <= set(repeats.B4_SCENARIOS) else 3 if set(scen) <= set(repeats.B3_SCENARIOS) else 2
            if batch != 4 and set(scen) & set(repeats.B4_SCENARIOS) or batch == 2 and set(scen) & set(
                    repeats.B3_SCENARIOS):
                ap.error("scenarios 4 5 6 (batch 2), 7 8 (batch 3) and 9 (batch 4) cannot be mixed")
            base_plan = {3: repeats.B3_PLAN, 4: repeats.B4_PLAN}.get(batch, repeats.B2_PLAN)
            plan = {}
            for m in a.model:
                mid, _, n = m.partition(":")
                plan[mid] = int(n) if n else base_plan[mid]
            if not a.key_cmd:
                ap.error("--model needs --key-cmd (batch 2 authenticates by API key)")
            key = subprocess.run(shlex.split(a.key_cmd), capture_output=True, text=True, check=True).stdout.strip()
            dflt = {3: repeats.B3_BUDGET_USD, 4: repeats.B4_BUDGET_USD}.get(batch, repeats.B2_BUDGET_USD)
            done = repeats.repeat_b2(ROOT, plan, scen, a.jobs, key, write_summary,
                                     a.budget if a.budget is not None else dflt, a.k_max, batch)
            del key
            print(f"batch {batch}: {sum(not d['error'] for d in done)}/{len(done)} without harness error")
            return 0
        if a.cmd == "repeat":
            if not a.scenario or len(a.scenario) != 1:
                ap.error("batch 1 takes exactly one --scenario")
            out = Path(a.out) if a.out else ROOT / "repeats" / a.scenario[0]
            done = repeats.repeat(ROOT, a.scenario[0], a.n, out, write_summary)
            print(f"scenario {a.scenario[0]}: {sum(not d['error'] for d in done)}/{len(done)} without harness error")
            return 0
        if a.cmd == "mcp-check":
            m = repeats.mcp_check(ROOT / "repeats" / "mcp" / "provenance.json")
            print(json.dumps([{k: c[k] for k in ("url", "failed", "structured")} for c in m["calls"]], indent=1))
            return 0
        repeats.write(ROOT, Path(a.out) if a.out else None)
        return 0
    if a.cmd == "verify":
        r = verify(Path(a.log))
        print(json.dumps({"ok": r.ok, "records": r.records, "last_hash": r.last_hash, "errors": r.errors}, indent=2))
        return 0 if r.ok else 1
    if a.cmd == "summary":
        s = write_summary(Path(a.log))
        print(summary.to_markdown(s))
        return 0
    m = mf.load(a.manifest)
    if a.cmd == "digest":
        print(mf.manifest_digest(m))
        return 0
    errs = mf.validate(m)
    print("ok" if not errs else "\n".join(errs))
    return 0 if not errs else 1


if __name__ == "__main__":
    sys.exit(main())
