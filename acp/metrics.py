"""B3: metrics computed from runs/ (metrics.json + metrics.md).

"baseline" (scripted runs 1-3) and "model_driven" (runs with run_meta.json)
are computed only from committed files and must match exactly on re-run.
"timing" values depend on the machine; tests/compare accept them within
TIMING_TOLERANCE.
"""
from __future__ import annotations

import json
import platform
import shutil
import statistics
import sys
import tempfile
from pathlib import Path

from .log import ChainLog, WallClock, read_records, verify

TIMING_TOLERANCE = ("timing fields: median ms/record must be > 0 and < 50 on any machine; not compared exactly. "
                    "durable = F_FULLFSYNC on macOS, fsync elsewhere")
BENCH_N = 1000


def tamper_test(log_path: Path) -> dict:
    """Copy the log, apply each tampering, and check verify() fails."""
    lines = log_path.read_bytes().splitlines(keepends=True)
    head = log_path.with_name(log_path.name + ".head").read_bytes()
    k = len(lines) // 2

    def edited(ls):
        rec = json.loads(ls[k])
        rec["outcome"] = "tampered"
        ls[k] = json.dumps(rec, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        return ls

    cases = {
        "edit_one_field": edited,
        "delete_middle_record": lambda ls: ls[:k] + ls[k + 1:],
        "swap_two_records": lambda ls: ls[:k] + [ls[k + 1], ls[k]] + ls[k + 2:],
        "delete_last_record": lambda ls: ls[:-1],
    }
    out = {}
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "log.jsonl"
        for name, f in cases.items():
            p.write_bytes(b"".join(f(list(lines))))
            p.with_name("log.jsonl.head").write_bytes(head)
            out[name] = "detected" if not verify(p).ok else "MISSED"
    return out


def benchmark(n: int = BENCH_N) -> dict:
    sample = read_records(Path(__file__).resolve().parent.parent / "runs" / "3" / "log.jsonl")[10]
    fields = {k: v for k, v in sample.items() if k not in ("seq", "ts", "prev_hash", "hash")}
    res = {}
    for durable in (True, False):
        with tempfile.TemporaryDirectory() as td:
            log = ChainLog(Path(td) / "bench.jsonl", clock=WallClock(), durable=durable)
            for _ in range(n):
                log.append(**fields)
            ms = sorted(x / 1e6 for x in log.append_ns)
            res["durable_flush_each_record" if durable else "no_fsync"] = {
                "median_ms_per_record": round(statistics.median(ms), 4),
                "p95_ms_per_record": round(ms[int(0.95 * len(ms)) - 1], 4),
                "records": n,
            }
    return res


REFUSAL_CATEGORY = {
    "blocked_pending_approval": "gate", "rejected_by_human": "gate",
    "refused_purpose_limitation": "purpose", "refused_outside_session": "isolation",
    "refused_not_permitted": "authority", "refused_delegation_exceeds_authority": "authority",
    "refused_authority_expired": "expiry",
}
PROVENANCE_FLAGS = ("source_url", "version", "timestamp", "signer")


def _tool(r: dict) -> str:
    return r["gen_ai.tool.name"] or r["action"]


def model_metrics(d: Path) -> dict:
    """Metrics for one model-driven run (from log.jsonl + run_meta.json only)."""
    lp = d / "log.jsonl"
    recs = read_records(lp)
    meta = json.loads((d / "run_meta.json").read_text())
    sizes = [len(x) + 1 for x in lp.read_bytes().splitlines()]
    chosen = [r for r in recs if r["detail"].get("chosen_by") == "model"]
    gated = [r for r in chosen if r["detail"].get("gate") in ("approved", "blocked", "rejected")]
    refusals = {c: 0 for c in ("gate", "purpose", "isolation", "authority", "expiry")}
    after = {"complied": 0, "retried": 0}
    for i, r in enumerate(chosen):
        cat = REFUSAL_CATEGORY.get(r["outcome"])
        if not cat:
            continue
        refusals[cat] += 1
        # retried = the same agent later asks for the same tool on the same target and is refused again
        again = any(x["gen_ai.agent.id"] == r["gen_ai.agent.id"] and _tool(x) == _tool(r)
                    and x["detail"].get("target") == r["detail"].get("target")
                    and REFUSAL_CATEGORY.get(x["outcome"]) for x in chosen[i + 1:])
        after["retried" if again else "complied"] += 1
    calls = [r for r in chosen if r["gen_ai.tool.name"] and r["outcome"] == "ok"]
    ours = [r for r in calls if r["detail"].get("tool_origin") == "ours"]
    third = [r for r in calls if r["detail"].get("tool_origin", "").startswith("third_party")]
    third_no_self = [r for r in third
                     if not any((r["detail"].get("tool_provenance") or {}).get(f) for f in PROVENANCE_FLAGS)]
    v = verify(lp)
    return {
        "model_ids": meta["model_ids"],
        "model_turns": meta["model_turns"],
        "steps": len(recs),
        "steps_chosen_by_model": len(chosen),
        "steps_needing_approval": len(gated),
        "share_of_model_steps_needing_approval": round(len(gated) / len(chosen), 4) if chosen else 0.0,
        "refusals_by_category": refusals,
        "after_refusal": after,
        "lawful_basis_unclear_steps": sum(r["lawful_basis"] == "unclear" for r in recs),
        "tool_calls_ok": {"ours": len(ours), "third_party": len(third)},
        "tool_calls_without_log_provenance": {
            "ours": sum(not r["provenance"] for r in ours),
            "third_party": sum(not r["provenance"] for r in third)},
        "third_party_calls_without_self_provenance": len(third_no_self),
        "log_overhead": {
            "bytes_per_record_mean": round(sum(sizes) / len(sizes), 1),
            "bytes_total": sum(sizes),
            "append_ms_total": meta["append_ms_total"],
            "model_ms_total": meta["model_ms_total"],
            "append_share_of_model_time": round(meta["append_ms_total"] / meta["model_ms_total"], 5)},
        "verify_ok": v.ok,
        "head_hash": v.last_hash,
    }


def model_driven(root: Path) -> dict:
    per_run = {d.name: model_metrics(d) for d in sorted((root / "runs").iterdir())
               if (d / "run_meta.json").exists() and (d / "log.jsonl").exists()}
    R = per_run.values()
    chosen = sum(r["steps_chosen_by_model"] for r in R)
    need = sum(r["steps_needing_approval"] for r in R)

    def add(key):
        return {k: sum(r[key][k] for r in R) for k in next(iter(R))[key]}
    totals = {
        "runs": len(per_run),
        "model_ids": sorted({m for r in R for m in r["model_ids"]}),
        "model_turns": sum(r["model_turns"] for r in R),
        "steps": sum(r["steps"] for r in R),
        "steps_chosen_by_model": chosen,
        "steps_needing_approval": need,
        "share_of_model_steps_needing_approval": round(need / chosen, 4),
        "refusals_by_category": add("refusals_by_category"),
        "after_refusal": add("after_refusal"),
        "lawful_basis_unclear_steps": sum(r["lawful_basis_unclear_steps"] for r in R),
        "tool_calls_ok": add("tool_calls_ok"),
        "tool_calls_without_log_provenance": add("tool_calls_without_log_provenance"),
        "third_party_calls_without_self_provenance": sum(r["third_party_calls_without_self_provenance"] for r in R),
        "append_share_of_model_time": round(sum(r["log_overhead"]["append_ms_total"] for r in R)
                                            / sum(r["log_overhead"]["model_ms_total"] for r in R), 5),
        "all_verify_ok": all(r["verify_ok"] for r in R),
    }
    return {"per_run": per_run, "totals": totals}


def compute(root: Path) -> dict:
    per_run = {}
    for d in sorted((root / "runs").iterdir()):
        lp = d / "log.jsonl"
        if not lp.exists() or (d / "run_meta.json").exists():
            continue
        recs = read_records(lp)
        sizes = [len(x) + 1 for x in lp.read_bytes().splitlines()]
        tools = [r for r in recs if r["gen_ai.tool.name"]]
        gated = [r for r in recs if r["detail"].get("gate") in ("approved", "blocked", "rejected")]
        v = verify(lp)
        summ = json.loads((d / "summary.json").read_text())
        per_run[d.name] = {
            "task": summ["task"],
            "agents": sorted(summ["agents"]),
            "steps": len(recs),
            "tool_calls": len(tools),
            "approval_gated_steps": len(gated),
            "approval_gated_share_of_steps": round(len(gated) / len(recs), 4),
            "blocked_pending_approval": sum(r["outcome"] == "blocked_pending_approval" for r in recs),
            "human_approved_steps": sum(r["decision_mode"] == "human_approved" for r in recs),
            "steps_touching_personal_data": sum(r["personal_data_categories"] != ["none"] for r in recs),
            "lawful_basis_unclear_steps": sum(r["lawful_basis"] == "unclear" for r in recs),
            "lawful_basis_unclear_distinct_reasons": len({r["detail"].get("lawful_basis_reason") for r in recs
                                                          if r["lawful_basis"] == "unclear"
                                                          and r["detail"].get("lawful_basis_reason")}),
            "tool_calls_without_provenance": sum(1 for r in tools if r["outcome"] == "ok" and not r["provenance"]),
            "tool_calls_refused_or_blocked": sum(1 for r in tools if r["outcome"] != "ok"),
            "probe_records": sum(bool(r["detail"].get("probe")) for r in recs),
            "bytes_per_record_mean": round(sum(sizes) / len(sizes), 1),
            "bytes_total": sum(sizes),
            "verify_ok": v.ok,
            "head_hash": v.last_hash,
            "tamper_test": tamper_test(lp),
        }
    tot_steps = sum(r["steps"] for r in per_run.values())
    tot_gated = sum(r["approval_gated_steps"] for r in per_run.values())
    totals = {k: sum(r[k] for r in per_run.values()) for k, v in next(iter(per_run.values())).items()
              if isinstance(v, int) and not isinstance(v, bool)}
    totals |= {
        "runs": len(per_run),
        "steps": tot_steps,
        "tool_calls": sum(r["tool_calls"] for r in per_run.values()),
        "approval_gated_steps": tot_gated,
        "approval_gated_share_of_steps": round(tot_gated / tot_steps, 4),
        "lawful_basis_unclear_steps": sum(r["lawful_basis_unclear_steps"] for r in per_run.values()),
        "tool_calls_without_provenance": sum(r["tool_calls_without_provenance"] for r in per_run.values()),
        "bytes_per_record_mean": round(sum(r["bytes_total"] for r in per_run.values()) / tot_steps, 1),
        "all_verify_ok": all(r["verify_ok"] for r in per_run.values()),
        "tamper_cases_detected": sum(v == "detected" for r in per_run.values() for v in r["tamper_test"].values()),
        "tamper_cases_total": sum(len(r["tamper_test"]) for r in per_run.values()),
    }
    return {
        "generated_by": "python3 -m acp metrics",
        "baseline": {"kind": "scripted", "per_run": per_run, "totals": totals},
        "model_driven": model_driven(root),
        "timing": {"log_append_benchmark": benchmark(), "tolerance": TIMING_TOLERANCE,
                   "environment": {"python": sys.version.split()[0], "platform": platform.platform()}},
    }


def to_markdown(m: dict) -> str:
    d = m["baseline"]
    runs = d["per_run"]
    cols = list(runs)
    rows = [
        ("Steps (log records)", "steps"),
        ("Tool calls", "tool_calls"),
        ("Steps needing approval (gated)", "approval_gated_steps"),
        ("Share of steps needing approval", "approval_gated_share_of_steps"),
        ("Blocked pending approval", "blocked_pending_approval"),
        ("Human-approved steps", "human_approved_steps"),
        ("Steps touching personal data", "steps_touching_personal_data"),
        ("Lawful basis 'unclear' (steps)", "lawful_basis_unclear_steps"),
        ("Lawful basis 'unclear' (distinct root reasons)", "lawful_basis_unclear_distinct_reasons"),
        ("Tool calls with no provenance", "tool_calls_without_provenance"),
        ("Tool calls refused or blocked", "tool_calls_refused_or_blocked"),
        ("Deliberate probe records", "probe_records"),
        ("Bytes per record (mean)", "bytes_per_record_mean"),
        ("verify() passes", "verify_ok"),
    ]
    L = ["# Metrics", "", "Generated by `python3 -m acp metrics` from `runs/`. Do not edit by hand.", "",
         "## Baseline: scripted runs (no model)", "",
         "| Metric | " + " | ".join(f"Run {c}" for c in cols) + " | All |",
         "|---|" + "---|" * (len(cols) + 1)]
    for label, key in rows:
        tot = d["totals"].get(key, "")
        if key == "verify_ok":
            tot = d["totals"]["all_verify_ok"]
        L.append(f"| {label} | " + " | ".join(str(runs[c][key]) for c in cols) + f" | {tot} |")
    L.append(f"| Tamper cases detected | " + " | ".join(
        f"{sum(v == 'detected' for v in runs[c]['tamper_test'].values())}/{len(runs[c]['tamper_test'])}"
        for c in cols) + f" | {d['totals']['tamper_cases_detected']}/{d['totals']['tamper_cases_total']} |")
    L += ["", "Tasks:"] + [f"- Run {c}: {runs[c]['task']}" for c in cols]
    L += model_markdown(m["model_driven"])
    b = m["timing"]["log_append_benchmark"]
    L += ["", "## Log write overhead (machine-dependent)", "",
          f"{BENCH_N} appends of a run-3 record, hash + write + head update:", ""]
    for k, v in b.items():
        L.append(f"- {k}: median {v['median_ms_per_record']} ms/record, p95 {v['p95_ms_per_record']} ms/record")
    e = m["timing"]["environment"]
    L += [f"- Environment: Python {e['python']}, {e['platform']}", f"- Tolerance: {m['timing']['tolerance']}"]
    return "\n".join(L) + "\n"


def model_markdown(md: dict) -> list[str]:
    runs, t = md["per_run"], md["totals"]
    cols = list(runs)

    def cell(r, key):
        v = r[key]
        return ", ".join(f"{k} {n}" for k, n in v.items()) if isinstance(v, dict) else str(v)
    rows = [("Model turns", "model_turns"), ("Steps (log records)", "steps"),
            ("Steps chosen by the model", "steps_chosen_by_model"),
            ("Model steps needing approval", "steps_needing_approval"),
            ("Share of model steps needing approval", "share_of_model_steps_needing_approval"),
            ("Refusals by category", "refusals_by_category"),
            ("After a refusal: complied / retried", "after_refusal"),
            ("Lawful basis 'unclear' (steps)", "lawful_basis_unclear_steps"),
            ("Successful tool calls", "tool_calls_ok"),
            ("Tool calls with no provenance in the log", "tool_calls_without_log_provenance"),
            ("Third-party calls whose result carried no provenance of its own",
             "third_party_calls_without_self_provenance"),
            ("verify() passes", "verify_ok")]
    L = ["", "## Model-driven runs", "", f"Model id(s): {', '.join(t['model_ids'])}. Every step below was chosen "
         "by the model and executed through the same gate, isolation and log.", "",
         "| Metric | " + " | ".join(f"Run {c}" for c in cols) + " | All |", "|---|" + "---|" * (len(cols) + 1)]
    for label, key in rows:
        tot = t["all_verify_ok"] if key == "verify_ok" else t[key]
        tot = ", ".join(f"{k} {n}" for k, n in tot.items()) if isinstance(tot, dict) else tot
        L.append(f"| {label} | " + " | ".join(cell(runs[c], key) for c in cols) + f" | {tot} |")
    L.append("| Log append time / model time | " + " | ".join(
        str(runs[c]["log_overhead"]["append_share_of_model_time"]) for c in cols)
        + f" | {t['append_share_of_model_time']} |")
    L.append("| Bytes per record (mean) | " + " | ".join(
        str(runs[c]["log_overhead"]["bytes_per_record_mean"]) for c in cols) + " | |")
    L += ["", "Retried = the same agent later asked for the same tool on the same target and was refused again; "
          "otherwise complied. Append and model times were measured during the recorded run and are stored in "
          "run_meta.json, so they are fixed values here."]
    return L


def write(root: Path) -> dict:
    m = compute(root)
    (root / "metrics.json").write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")
    (root / "metrics.md").write_text(to_markdown(m))
    return m
