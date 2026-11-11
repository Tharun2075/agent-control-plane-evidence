# Batch 12: scripted attacker (E1) after the paper-fix12 changes (pre-registered; committed before any run)

Why: batch 5 left 30/540 E1 bypasses at the paper-v1.2 code, all in the two classes it marked
out of scope (approval-forgery 10, tool-direct-file-access 20). paper-fix12 adds HMAC-signed
approvals (commit 82bf552) and an in-process path guard on tool bodies (8d76c0b, cb5e2aa).
Batch 12 re-runs the same model-free attacker at the new code. No model is called.

## Plan
- Attacker: acp/attacker.py unchanged since paper-v1.2 apart from what the registered hashes
  below show; same 27 tricks, 20 attempts each, n = 540, seed 20261110, `attacker.run`
  (E1 adaptive stream, as batch 5 E1). Payloads are drawn from the same seeded stream; where
  a refusal now replaces a former bypass the adaptive level may move, as in every E1 run.
- Code: the files listed in acp/batch5.py CODE, SHA-256 in repeats/batch12/code-sha256.json.
  `tools/batch12.py run` refuses to start when the working code differs.
- Before = the committed batch-5 E1 after-phase records (repeats/batch5/e1-after, paper-v1.2
  code). They are recorded results, not re-run.
- After = repeats/batch12/e1-after (attempts.jsonl, per-family logs, meta.json).

## Predictions (stated before the run)
- P12a: approval-forgery bypasses 10 -> 0 (forged approval file fails the MAC check).
- P12b: tool-direct-file-access bypasses 20 -> 0 (path guard refuses the out-of-session open).
- P12c: every other class stays at 0; total E1 bypasses 0/540 (Wilson 95% upper bound reported).
- H1 (T6) unchanged: every attempt leaves >= 1 gate record.

## Metrics
Per-class and per-family bypass counts before and after, total k/540 with Wilson 95% interval.
batch5's OUT_OF_SCOPE_TRICKS and attacker.FIXABLE are left as they are (make verify re-checks
batch 5); batch 12 counts all 540 attempts as in scope.

## Checks
`python3 tools/batch12.py --check` (in `make verify`): every meta.json carries the registered
code hashes, dirty=false for acp/, started after this file's first commit, and summary.json
regenerates from the records.

## Limits
The path guard is an in-process audit hook, not an OS sandbox; the HMAC key lives in the same
process. The attacker is the scripted one only; model runs at this code are the owner's rerun.
