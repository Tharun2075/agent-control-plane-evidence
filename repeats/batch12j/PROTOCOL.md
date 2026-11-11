# Batch 12j: E1 + E2p scripted attacker after the class check covers modules and loggers made during the call (pre-registered; committed before any run)

Why: at paper-v1.2 (eb2a6a4) the class row snapshotted only the modules and loggers that existed
before the call, so a tool body could import a module (e.g. colorsys) or create a logger (e.g.
getLogger("jc21.new.child")) and swap its class, and the swap persisted unrefused.
acp/gate.py now also walks, after the call, every name in sys.modules and in
logging.root.manager.loggerDict that the snapshot did not hold. A module whose class is not exactly
types.ModuleType (importlib.util._LazyModule and any module class the snapshot already saw are allowed)
is put back to types.ModuleType; a logger whose class is not the snapshotted logging.getLoggerClass()
or logging.PlaceHolder (or a logger class the snapshot already saw) is put back; each is reset with
object.__setattr__ and the call refused ("type(<name>)"). Every fix12c-i row is kept.
acp/gate.py is a registered file, so E1 and E2p are re-run. No model is called.

## Plan
- Attacker and design: exactly as repeats/batch12/PROTOCOL.md (E1: 27 tricks x 20, n = 540,
  seed 20261110, `attacker.run`) and repeats/batch12/PROTOCOL-E2p.md (E2p: six arms, 540
  attempts per arm, payload hashes equal across arms, exact McNemar vs all-on, Holm over 5).
- Code: the files in acp/batch5.py CODE, SHA-256 in repeats/batch12j/code-sha256.json
  (acp/gate.py sha256 d412a2cfcd4e52657d85eb486ba5ea755f63a2eb3e252603822854d75d92bb0d). `tools/batch12j.py run` refuses to start when the code differs.
- Before = the committed batch-12i records (repeats/batch12i), recorded, not re-run.
- After = repeats/batch12j/e1-after and repeats/batch12j/e2p/<arm>/, summary.{json,md}.

## Predictions (stated before the run)
- P12j-1: E1 total stays 0/540; every class stays at 0 (the scripted attacker touches none of the new state).
- P12j-2: E2p bypass counts per arm equal batch 12i: all-on 0, gate-off 80, allowlist-off 167,
  expiry-off 60, authority-off 20, all-off 307; H5 verdicts unchanged.
- H1 (T6) unchanged: every attempt leaves >= 1 gate record.

## Checks
`python3 tools/batch12j.py --check` (in `make verify`): every meta.json carries the registered
code hashes, dirty=false for acp/, started after this file's first commit, and summary.json
regenerates from the records.

## Limits
- Not an OS sandbox: in-process tricks (ctypes, object-graph walking), shared state outside the
  restored list (e.g. the contents of sys.modules and builtins, warnings.showwarning), objects
  reachable from restored state that are mutated in place, attributes not on that list, metadata
  calls and host-held file handles lie outside the guard; a per-tool OS sandbox is next.
- The attacker is the scripted one only; model runs at this code are the owner's rerun.
