"""L5: benign refusals by check and suite, and the share of the benign-utility loss each check causes.

Part A (per-check refusals): batch 14 gated benign runs (B1, 9 victims x 37 tasks). Every gated call
carries the verdict of each check (`chk`), so for each check we count the runs in which that check
alone would refuse at least one call; and, in gate order, the runs whose first refusal is that check.
Part B (utility loss): pair each batch-14 gated benign run with the plain run of the same victim and
user task (batches 6 and 7). A lost task is one the plain run completes and the gated run does not;
it is attributed to the check behind the gated run's first refusal (`none` = no refusal: the model
itself failed the task).
"""
from collections import Counter, defaultdict

from common import CHECKS, first_failing, reason_check, runs, wilson, write_csv


def benign(batch, arm):
    return [r for r in runs(batch, f"*__{arm}__B1.jsonl") if r["kind"] == "benign"]


def first_reason(r):
    for c in r.get("calls") or []:
        k = reason_check(c.get("gate"))
        if k:
            return k
    return "none"


def first_chk(r):
    """Check behind the run's first refused call, in gate order on that call."""
    for c in r.get("calls") or []:
        k = first_failing(c.get("chk") or {})
        if k:
            return k
    return None


def main():
    gated = benign("batch14", "gated")
    models = sorted({r["model"] for r in gated})
    rows = []
    for check in CHECKS + tuple("first:" + c for c in CHECKS):
        for scope in ["all", "banking", "slack"]:
            row = {"check": check, "suite": scope}
            for m in models + ["ALL"]:
                rs = [r for r in gated if (m == "ALL" or r["model"] == m) and scope in ("all", r["suite"])]
                if check.startswith("first:"):
                    k = sum(first_chk(r) == check[6:] for r in rs)
                else:
                    k = sum(any((c.get("chk") or {}).get(check) is False for c in r["calls"]) for r in rs)
                lo, hi = wilson(k, len(rs))
                row[m] = f"{k}/{len(rs)} [{lo:.2f},{hi:.2f}]"
            rows.append(row)
    print(write_csv("benign_refusals_by_check.csv", rows))

    plain = {}
    for b in ("batch6", "batch7"):
        for r in benign(b, "plain"):
            plain[(r["model"], r["suite"], r["ut"])] = r
    loss = defaultdict(Counter)
    tot = Counter()
    for r in gated:
        p = plain.get((r["model"], r["suite"], r["ut"]))
        if p is None:
            continue
        tot[r["suite"]] += 1
        if p.get("utility") and not r.get("utility"):
            loss[r["suite"]][first_reason(r)] += 1
    out = []
    for suite in ("banking", "slack", "all"):
        c = Counter()
        for s in ("banking", "slack"):
            if suite in (s, "all"):
                c.update(loss[s])
        n = sum(c.values())
        out.append({"suite": suite, "paired_runs": sum(tot.values()) if suite == "all" else tot[suite],
                    "lost_tasks": n, **{k: c[k] for k in CHECKS + ("other", "none")},
                    "allowlist_share": f"{c['allowlist'] / n:.2f}" if n else "",
                    "allowlist_share_ci95": "[%.2f,%.2f]" % wilson(c["allowlist"], n) if n else ""})
    print(write_csv("benign_loss_attribution.csv", out))
    for o in out:
        print(o)
    for r in rows:
        if r["suite"] == "all":
            print(r["check"], r["ALL"])


if __name__ == "__main__":
    main()
