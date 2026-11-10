"""CLI: python3 -m acp {reproduce,model-run,verify-all,metrics,verify,summary,digest,validate}"""
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
        for log in sorted((ROOT / "runs").glob("*/log.jsonl")):
            r = verify(log)
            bad += not r.ok
            print(f"{log.parent.name}: {'ok' if r.ok else 'FAIL'} {r.records} records" +
                  ("" if r.ok else " " + "; ".join(r.errors[:3])))
        return 1 if bad else 0
    if a.cmd == "metrics":
        if a.out:
            Path(a.out).write_text(json.dumps(metrics.compute(ROOT), indent=2, sort_keys=True) + "\n")
        else:
            metrics.write(ROOT)
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
