# Batch 12 addendum E2p: paired ablation at the paper-fix12 code (pre-registered)

Same design as repeats/batch5/PROTOCOL-E2p.md: arms all-on, gate-off, allowlist-off,
expiry-off, authority-off, all-off; per-attempt RNG `random.Random(f"{seed}:{fam}:{trick}:{k}")`,
adapt = k % 4, 540 attempts per arm, seed 20261110, identical payload hashes asserted across
all six arms (a mismatch stops the analysis). Exact two-sided McNemar per arm against all-on,
Holm over 5 comparisons; H5 holds for X when c > b and Holm p < 0.05.

Differences from batch 5:
- Code: repeats/batch12/code-sha256.json (paper-fix12).
- No arm switches off the HMAC approval check or the tool path guard; both stay on in every
  arm. The ablation covers the four batch-5 controls only.
- Output: repeats/batch12/e2p/<arm>/ and repeats/batch12/summary.{json,md}. The meta.json
  `protocol` field is written by acp/batch5.run_e2p and reads "repeats/batch5/PROTOCOL-E2p.md";
  for these runs this file is the protocol (known label, not changed to keep batch 5 code fixed).

Predictions: all-on bypasses 35 -> 0 (the 35 were approval and session family attempts that
the HMAC check and the path guard now refuse); H5 still holds for allowlist-off, authority-off
and all-off. Before = repeats/batch5/e2p (recorded, not re-run).
