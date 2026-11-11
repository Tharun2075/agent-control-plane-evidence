"""L3: paired exact McNemar for E2p (batch 12c), each control-off arm against all-on.

Pairs the 540 payloads by id. b = payloads that bypass with all controls on but not with the
arm; c = the reverse. All-on lets no payload through, so b = 0 by construction and the exact
test reduces to a one-sided binomial: p = 0.5**c. Holm over the five arms.
"""
import json
import os

from common import ROOT, write_csv

ARMS = ("gate-off", "allowlist-off", "expiry-off", "authority-off", "all-off")


def load(arm):
    path = os.path.join(ROOT, "repeats", "batch12c", "e2p", arm, "attempts.jsonl")
    with open(path) as fh:
        return {r["id"]: r for r in map(json.loads, fh) if r}


def main():
    base = load("all-on")
    rows = []
    for arm in ARMS:
        a = load(arm)
        assert set(a) == set(base), arm
        assert all(a[i]["payload_sha256"] == base[i]["payload_sha256"] for i in base), arm
        b = sum(base[i]["bypass"] and not a[i]["bypass"] for i in base)
        c = sum(a[i]["bypass"] and not base[i]["bypass"] for i in base)
        p = 0.5 ** c if b == 0 else None
        rows.append({"arm": arm, "pairs": len(base), "b": b, "c": c, "p_one_sided": p})
    order = sorted(range(len(rows)), key=lambda i: rows[i]["p_one_sided"])
    m, run = len(rows), 0.0
    for rank, i in enumerate(order):
        run = max(run, min(1.0, (m - rank) * rows[i]["p_one_sided"]))
        rows[i]["p_holm"] = run
    for r in rows:
        r["p_one_sided"] = f"{r['p_one_sided']:.3g}"
        r["p_holm"] = f"{r['p_holm']:.3g}"
    print(write_csv("mcnemar_exact.csv", rows))
    for r in rows:
        print(r)


if __name__ == "__main__":
    main()
