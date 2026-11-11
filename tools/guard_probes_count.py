"""Count the probe routes in docs/GUARD-PROBES.md from its table rows.

Each row: | id | route | round | n | then | fix | now |
n is the number of routes the row stands for (1 unless the verdict only gave a count).
then is one of: refused (the guard raised and the call did not run), held (the call
ran or was refused but nothing reached outside the session: state restored, or no
leak seen), escaped in scope, out of scope.
Usage: python3 tools/guard_probes_count.py [docs/GUARD-PROBES.md]
"""
import sys

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
        yield int(n), then, now


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "docs/GUARD-PROBES.md"
    total = refused = held = fixed = out = out_now = 0
    for n, then, now in rows(path):
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


if __name__ == "__main__":
    main()
