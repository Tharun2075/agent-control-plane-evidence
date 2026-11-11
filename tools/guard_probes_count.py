"""Count the probe routes in docs/GUARD-PROBES.md from its table rows.

Each row: | id | route | round | n | then | fix | now |
Column meanings: the "Columns:" paragraph of docs/GUARD-PROBES.md.
A "refused" row whose route a verdict lists after an UNSPLIT phrase exits 1 (it is held).
Usage: python3 tools/guard_probes_count.py [docs/GUARD-PROBES.md] [verdict_dir]
verdict_dir holds VERDICT-paper-<round>.md (default: the repo's parent directory).
"""
import os
import re
import sys

UNSPLIT = ("restored or refused", "refused or restored")
TOKEN = re.compile(r"\b([A-Z])(\d+)([a-z]?)\b(?:-\1(\d+)\b)?")

THEN = ("refused", "held", "escaped in scope", "out of scope")
NOW = ("refused", "held", "out of scope")


def rows(path):
    for line in open(path, encoding="utf-8"):
        if not line.startswith("| G"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 7:
            sys.exit(f"bad row ({len(cells)} cells): {line.strip()}")
        rid, _route, _round, n, then, fix, now = cells
        if then not in THEN:
            sys.exit(f"{rid}: unknown outcome {then!r}")
        if now not in NOW:
            sys.exit(f"{rid}: unknown current outcome {now!r}")
        if then == "escaped in scope" and fix in ("", "-"):
            sys.exit(f"{rid}: escaped but no fix named")
        yield rid, _route, _round, int(n), then, now


def route_tokens(route):
    """Route ids in the route cell before "(", ranges such as P4-P7 expanded."""
    toks = []
    for m in TOKEN.finditer(route.split("(")[0]):
        letter, a, suffix, b = m.groups()
        if b and not suffix:
            toks += [f"{letter}{i}" for i in range(int(a), int(b) + 1)]
        else:
            toks.append(f"{letter}{a}{suffix}")
    return toks


def unsplit_hits(rid, route, rnd, verdict_dir):
    """Lines of VERDICT-paper-<rnd>.md that list a route of this row after an UNSPLIT phrase."""
    vpath = os.path.join(verdict_dir, f"VERDICT-paper-{rnd}.md")
    if not os.path.exists(vpath):
        return []
    toks = [t.lower() for t in route_tokens(route)]
    hits = []
    for i, line in enumerate(open(vpath, encoding="utf-8"), 1):
        low = line.lower()
        for phrase in UNSPLIT:
            if phrase not in low:
                continue
            tail = low.split(phrase, 1)[1]
            if any(re.search(rf"\b{re.escape(t)}\b", tail) for t in toks):
                hits.append(f"{rid}: VERDICT-paper-{rnd}.md:{i} says '{phrase}' (not split per route) "
                            f"but row says refused. Fix: set then (and now) to held in "
                            f"docs/GUARD-PROBES.md row {rid}")
                break
    return hits


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "docs/GUARD-PROBES.md"
    here = os.path.dirname(os.path.abspath(__file__))
    verdict_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(os.path.dirname(here))
    check = any(f.startswith("VERDICT-paper-") and f.endswith(".md") for f in os.listdir(verdict_dir))
    if not check:
        print(f"verdict cross-check skipped: {verdict_dir}", file=sys.stderr)
    total = refused = held = fixed = out = out_now = 0
    hits = []
    for rid, route, rnd, n, then, now in rows(path):
        if check and then == "refused":
            hits += unsplit_hits(rid, route, rnd, verdict_dir)
        total += n
        refused += n if then == "refused" else 0
        held += n if then == "held" else 0
        fixed += n if then == "escaped in scope" else 0
        out += n if then == "out of scope" else 0
        out_now += n if now == "out of scope" else 0
    print(f"routes_total={total}")
    print(f"refused_first_try={refused}")
    print(f"held_first_try={held}")
    print(f"did_not_get_through_first_try={refused + held}")
    print(f"escaped_in_scope_then_fixed={fixed}")
    print(f"out_of_scope_then={out}")
    print(f"out_of_scope_now={out_now}")
    if hits:
        sys.exit("\n".join(hits))


if __name__ == "__main__":
    main()
