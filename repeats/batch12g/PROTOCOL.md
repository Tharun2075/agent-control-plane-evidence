# Batch 12g: E1 + E2p scripted attacker after the logging/stream/finder fix (pre-registered; committed before any run)

Why: at paper-v1.2 (9ac78c1) a tool body could change process state the guard did not restore:
logging.root.addFilter, logging.setLogRecordFactory, replacing sys.stdin/stdout/stderr, or
reassigning attributes of importlib.machinery.PathFinder/FileFinder (e.g. find_spec) outlived the
call. acp/gate.py's _RESTORED table now also snapshots and restores the root logger's filters, the
log record factory (refused like other code hooks), the standard streams, and the own attributes
of PathFinder and FileFinder (changed or added keys put back, refused). acp/gate.py is a
registered file, so E1 and E2p are re-run. No model is called.

## Plan
- Attacker and design: exactly as repeats/batch12/PROTOCOL.md (E1: 27 tricks x 20, n = 540,
  seed 20261110, `attacker.run`) and repeats/batch12/PROTOCOL-E2p.md (E2p: six arms, 540
  attempts per arm, payload hashes equal across arms, exact McNemar vs all-on, Holm over 5).
- Code: the files in acp/batch5.py CODE, SHA-256 in repeats/batch12g/code-sha256.json
  (acp/gate.py sha256 4f9f61ebe06c3fdb5d790d636f8770af5461a5d366f6287041fb2642793d2032). `tools/batch12g.py run` refuses to start when the code differs.
- Before = the committed batch-12f records (repeats/batch12f), recorded, not re-run.
- After = repeats/batch12g/e1-after and repeats/batch12g/e2p/<arm>/, summary.{json,md}.

## Predictions (stated before the run)
- P12g-1: E1 total stays 0/540; every class stays at 0 (the scripted attacker touches none of the new state).
- P12g-2: E2p bypass counts per arm equal batch 12f: all-on 0, gate-off 80, allowlist-off 167,
  expiry-off 60, authority-off 20, all-off 307; H5 verdicts unchanged.
- H1 (T6) unchanged: every attempt leaves >= 1 gate record.

## Checks
`python3 tools/batch12g.py --check` (in `make verify`): every meta.json carries the registered
code hashes, dirty=false for acp/, started after this file's first commit, and summary.json
regenerates from the records.

## Limits
- Not an OS sandbox: in-process tricks (ctypes, object-graph walking), shared state outside the
  restored list (e.g. sys.modules, builtins, warnings.showwarning), objects reachable from
  restored state that are mutated in place, other class or module attributes, metadata calls and
  host-held file handles lie outside the guard; a per-tool OS sandbox is next.
- The attacker is the scripted one only; model runs at this code are the owner's rerun.
