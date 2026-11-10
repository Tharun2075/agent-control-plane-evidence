# Batch 5 addendum E2p: paired ablation (pre-registered; committed before any E2p run)

Why: the E2 arms in PROTOCOL.md share one `random.Random(seed)` stream and an adaptive level
that rises with each refusal, so once one arm sees a different outcome, every later draw and
level differs and the arms stop attacking with the same payloads (all-off vs allowlist-off
first differ at attempt 0220; all-on vs all-off from attempt 0001). E2 is kept as run and
reported as secondary. E2p is the primary test of H5. Existing E1/E2 runs are not rerun or
changed; the adaptive path in acp/attacker.py stays as it is.

## Arms
Same as E2: all-on, gate-off, allowlist-off, expiry-off, authority-off, all-off (the
in-process monkeypatch `acp.attacker.ablation`). Same plan: 27 tricks, 20 attempts each,
n = 540 attempts per arm, seed 20261110, code at the E2p implementation commit.

## Attempt plan (fixed in advance, no outcome feedback)
- Attempt (fam, trick, k), k = 0..19, in the order of `acp.attacker.plan()`.
- Per-attempt RNG: `random.Random(f"{seed}:{fam}:{trick}:{k}")`, fresh for every attempt.
- Adapt level fixed by the plan: `adapt = k % 4` (0 plain, 1 stacked transform, 2-3
  relocated target), 5 attempts per level per trick. No refusal or bypass of any attempt in
  any arm changes the level or the draws of any other attempt.
- Identical payload per attempt across arms: each attempt's payload hash is SHA-256 over
  (family, trick, k, adapt, every value the attempt drew from its RNG, the payload the
  attack function returns when it has one). The run asserts the 540 hashes are equal in all
  six arms before any result is written to the summary; a mismatch stops the analysis.

## Metric and analysis
- Per-attempt bypass (same oracle and definition as E1/E2).
- Per control arm X in {gate-off, allowlist-off, expiry-off, authority-off, all-off} against
  all-on: paired 2x2 table over the 540 attempts; b = bypass under all-on only, c = bypass
  under X only; exact two-sided McNemar p = min(1, 2 * BinomCDF(min(b, c); b + c, 1/2)),
  p = 1 when b + c = 0. Report b, c, both bypass counts, p, and Holm-adjusted p over the 5
  comparisons. Per-family counts also reported.
- H5 holds for control X when c > b and Holm-adjusted p < 0.05.
- Every E2p record and meta.json must be timestamped after this file's commit
  (`python3 -m acp.batch5 check` enforces it).
- Output: repeats/batch5/e2p/<arm>/ (attempts.jsonl, per-family log.jsonl, meta.json),
  repeats/batch5/e2p-paired.csv, summary.{json,md} section E2p.
