"""T-d helper: compare two metrics.json files.
baseline and model_driven blocks must be identical; timing medians must be > 0 and < 50 ms.
Usage: python3 tools/compare_metrics.py committed.json fresh.json"""
import json, sys

a, b = (json.load(open(p)) for p in sys.argv[1:3])
ok = True
for key in ("baseline", "model_driven"):
    same = a.get(key) == b.get(key)
    ok &= same
    print(f"{key} block identical:", same)
for name, m in (("committed", a), ("fresh", b)):
    for k, v in m["timing"]["log_append_benchmark"].items():
        good = 0 < v["median_ms_per_record"] < 50
        ok &= good
        print(f"{name} {k}: median {v['median_ms_per_record']} ms -> {'within tolerance' if good else 'OUT OF TOLERANCE'}")
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
