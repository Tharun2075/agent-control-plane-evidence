# Round-6 analyses (`make analysis`; outputs in analysis/out/)

All five scripts read the committed run records only. No model or cloud call is made.

- **mcnemar_exact.py**: E2p, one-sided exact McNemar on the 540 paired payloads per ablation arm, Holm over five arms. Every arm has b=0, so p = 0.5^c. gate-off c=80 (p_Holm 2.5e-24), allowlist-off c=167 (2.1e-50), expiry-off c=60 (1.7e-18), authority-off c=20 (9.5e-07), all-off c=307 (1.9e-92).
- **benign_refusals.py**: batch 14 gated benign runs paired with batch 6+7 plain benign runs on the same task. 141 of 333 pairs lose utility under the gate. The allowlist decides 120 of them (85% [78, 90]), the action check 11, and 10 are the model's own failure. By suite, the allowlist share is banking 57% and slack 90%. The authority check refuses no benign run.
- **checks_reached.py**: the deepest check each attacked run's target call reached (batches 10, 11b, 14, 15). "passed" means the call passed every check, not that the attack succeeded.
- **config_replay.py**: (a) the measured batch 8 single-check arms vs the batch 7 full gate. Allowlist alone: 13/228 attacks, 93/216 benign. Approval alone: 90/234 attacks, 135/211 benign. Full gate: 7/230 attacks, 86/215 benign. (b) A counterfactual replay of the recorded per-check verdicts: every subset containing the allowlist stops every outside-task target call (54/236 pass, all inside the task). Allowlist alone refuses 167/327 benign runs, the full set 170/327.
- **run_inventory.py**: per batch and victim, the exact provider model id, UTC dates, runs, tool calls, tokens and summed run hours.

Caveats: gated trajectories stop at the first refusal, so replayed benign costs for smaller subsets are lower bounds. Per-check verdicts (`chk`) exist only on target calls that reached the gate. Batches 14 and 15 record no authority verdict.
