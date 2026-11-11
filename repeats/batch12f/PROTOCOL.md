# Batch 12f: E1 + E2p scripted attacker after the process-hook fix (pre-registered; committed before any run)

Why: at paper-v1.2 (1fecdc8) a tool body could register a process-global hook the guard did not
cover: os.register_at_fork(after_in_child=...) ran tool code in a later host fork, outside the
guard, and could read another session's file. acp/gate.py now holds one table (_RESTORED): fork
hooks, codec search functions and faulthandler are refused like atexit, audit hooks, threads,
signals and weakref.finalize; interpreter hooks (except/unraisable/display/breakpoint, asyncgen),
import machinery (meta_path, path_hooks, path_importer_cache), sys.path, os.environ, profile and
trace (sys and threading), root logging, gc.callbacks and copyreg.dispatch_table are snapshotted
and restored after each call, guarded. acp/gate.py is a registered file, so E1 and E2p are re-run.
No model is called.

## Plan
- Attacker and design: exactly as repeats/batch12/PROTOCOL.md (E1: 27 tricks x 20, n = 540,
  seed 20261110, `attacker.run`) and repeats/batch12/PROTOCOL-E2p.md (E2p: six arms, 540
  attempts per arm, payload hashes equal across arms, exact McNemar vs all-on, Holm over 5).
- Code: the files in acp/batch5.py CODE, SHA-256 in repeats/batch12f/code-sha256.json
  (acp/gate.py sha256 839c46b8d6584ed94a9106adcb5f36913f49ede98b77ed85598cae7907b728c4). `tools/batch12f.py run` refuses to start when the code differs.
- Before = the committed batch-12e records (repeats/batch12e), recorded, not re-run.
- After = repeats/batch12f/e1-after and repeats/batch12f/e2p/<arm>/, summary.{json,md}.

## Predictions (stated before the run)
- P12f-1: E1 total stays 0/540; every class stays at 0 (the scripted attacker registers no hooks).
- P12f-2: E2p bypass counts per arm equal batch 12e: all-on 0, gate-off 80, allowlist-off 167,
  expiry-off 60, authority-off 20, all-off 307; H5 verdicts unchanged.
- H1 (T6) unchanged: every attempt leaves >= 1 gate record.

## Checks
`python3 tools/batch12f.py --check` (in `make verify`): every meta.json carries the registered
code hashes, dirty=false for acp/, started after this file's first commit, and summary.json
regenerates from the records.

## Limits
- Not an OS sandbox: in-process tricks (ctypes, object-graph walking), shared state outside the
  restored list (e.g. sys.modules, builtins, warnings.showwarning), metadata calls and host-held
  file handles lie outside the guard; a per-tool OS sandbox is next.
- The attacker is the scripted one only; model runs at this code are the owner's rerun.
