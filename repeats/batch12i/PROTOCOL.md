# Batch 12i: E1 + E2p scripted attacker after the bound-path-function and class-snapshot fix (pre-registered; committed before any run)

Why: at paper-v1.2 (3caef1d) a tool body could swap the class of posixpath to a ModuleType subclass
whose __getattribute__ lied about realpath, so a later call read another session's file; class swaps
of builtins, importlib, json and any named logger were allowed and persisted; and a class property
with a no-op setter (e.g. on RootLogger.level) made the restore loop spin forever.
acp/gate.py now binds every function its path and event checks use at import (os.fsdecode,
os.fsencode, os.fspath, os.PathLike, os.lstat, os.readlink, os.getcwd, sys.modules, gc.collect,
sys.getprofile/setprofile, the sqlite3 authorizer constants, ModuleSpec), resolves paths with its own
port of posixpath.realpath, and runs on a private builtins dict. One row snapshots type() of every
module in sys.modules and every logger (root included) before each call; a changed class is put back
and the call refused. The gc.collect + restore loop runs at most 3 passes, then refuses with
"(not restored)". acp/gate.py is a registered file, so E1 and E2p are re-run. No model is called.

## Plan
- Attacker and design: exactly as repeats/batch12/PROTOCOL.md (E1: 27 tricks x 20, n = 540,
  seed 20261110, `attacker.run`) and repeats/batch12/PROTOCOL-E2p.md (E2p: six arms, 540
  attempts per arm, payload hashes equal across arms, exact McNemar vs all-on, Holm over 5).
- Code: the files in acp/batch5.py CODE, SHA-256 in repeats/batch12i/code-sha256.json
  (acp/gate.py sha256 3e777e52ddd65e3cd31faa083635e209e7ebbb646f4bd22e56d744b6244d1ff4). `tools/batch12i.py run` refuses to start when the code differs.
- Before = the committed batch-12h records (repeats/batch12h), recorded, not re-run.
- After = repeats/batch12i/e1-after and repeats/batch12i/e2p/<arm>/, summary.{json,md}.

## Predictions (stated before the run)
- P12i-1: E1 total stays 0/540; every class stays at 0 (the scripted attacker touches none of the new state).
- P12i-2: E2p bypass counts per arm equal batch 12h: all-on 0, gate-off 80, allowlist-off 167,
  expiry-off 60, authority-off 20, all-off 307; H5 verdicts unchanged.
- H1 (T6) unchanged: every attempt leaves >= 1 gate record.

## Checks
`python3 tools/batch12i.py --check` (in `make verify`): every meta.json carries the registered
code hashes, dirty=false for acp/, started after this file's first commit, and summary.json
regenerates from the records.

## Limits
- Not an OS sandbox: in-process tricks (ctypes, object-graph walking), shared state outside the
  restored list (e.g. the contents of sys.modules and builtins, warnings.showwarning), objects
  reachable from restored state that are mutated in place, attributes not on that list, metadata
  calls and host-held file handles lie outside the guard; a per-tool OS sandbox is next.
- The attacker is the scripted one only; model runs at this code are the owner's rerun.
