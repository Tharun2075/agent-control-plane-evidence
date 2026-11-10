# Batch 5: what was tried before pre-registration

This file records only what can be shown from kept sources: the git history of
`paper-experiments`, the `internal-history` branch, and the work folder the
run was made from. Nothing below is reconstructed from memory.

## What exists

| When (UTC, 2026-11-10) | Evidence | What it shows |
|---|---|---|
| 10:49:47 | commit 86c8f54 (main) | last core change before batch 5 work |
| 11:28 | stage line in the run's own report | "build: acp/attacker.py (seeded, deterministic) + WPT URL corpus; acp/batch5.py driver" |
| 11:39:23 | commit 7a53fe5 | attacker, url corpus, ablation arms, runs 4-6 replay committed together |
| 11:39:24 | commit 53dba5a | E1/E2/E3/E5 driver, summary, CSV tables, T7 checker |
| 11:40:52 | commit a995062 | SHA-256 of code files recorded in every run meta |
| 11:41:21 | commit 6e007e2 | PROTOCOL.md pre-registered |
| 11:41:39 | commit 503adeb | corpus note corrected (deviation D0); no run yet |
| 11:41:48 | commit ea5138e | first result: E1 before |

So the attacker and driver were written between about 11:28 and 11:39 and
committed 2 minutes before the protocol. PROTOCOL.md says: "Development dry
runs into temp dirs (not repeats/batch5) were used to build the attacker; they
are not results."

## What does not exist

- No dry-run output was kept. No temp dirs from that window remain, and no
  dry-run file was ever written under `repeats/`.
- No intermediate commits: the attacker appears complete in 7a53fe5. Edits
  made before that commit (trick list, PER_TRICK, seed) are not recorded.
- `internal-history` has no batch 5 work (its last commit, 13a45b9, is 07:49Z).
- The session transcripts of the build (two seats hit their limit and handed
  over) were not found; the wrapper log holds only start/limit/finish lines.

Therefore we cannot say how many dry runs were made, what they returned, or
whether any trick or parameter was changed after seeing a dry-run result. A
reader should treat the trick set and PER_TRICK=20 as chosen by the authors
with no verifiable record of being fixed before the attacker had been run.
What is verifiable: the seed (20261110), the code SHA-256 in every run meta,
and that every committed result comes after 6e007e2.
