"""Write or check the batch 11b outputs (repeats/batch11b/PROTOCOL-ADDENDUM.md).

  python3 tools/batch11b_summary.py            # regenerate summary.{md,json}, CSVs
  python3 tools/batch11b_summary.py --check    # exit 1 if a committed output differs or a chain fails
"""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from acp import batch11b  # noqa: E402
from acp.log import verify  # noqa: E402


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--check", action="store_true")
    a = p.parse_args(argv)
    if not (ROOT / "repeats" / "batch11b" / "runs").is_dir():
        print("batch11b: no runs yet")
        return 0
    files = batch11b.build(ROOT)
    if not a.check:
        for rel, text in files.items():
            (ROOT / rel).write_text(text)
        print("wrote", ", ".join(sorted(files)))
        return 0
    bad = 0
    for rel, text in files.items():
        f = ROOT / rel
        if not f.exists() or f.read_text() != text:
            bad += 1
            print(f"{rel} differs")
    for log in sorted((ROOT / "repeats" / "batch11b" / "logs").glob("*.jsonl")):
        r = verify(log)
        bad += not r.ok
        print(f"{log.relative_to(ROOT)}: {'ok' if r.ok else 'FAIL'} {r.records} records")
    print("batch11b summary identical:", bad == 0)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
