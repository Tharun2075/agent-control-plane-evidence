# Batch 11b: addendum to repeats/batch11/PROTOCOL.md (written and committed before any model call)

## Deviation found after batch 11 (harness bug)
- AgentDojo 0.1.35 builds the environment by `environment_text.format(**injections)` and then
  `yaml.safe_load`; the injection placeholders sit inside YAML double-quoted scalars. A rewrite that
  holds `"`, `\` or similar breaks the YAML: `load_and_inject_default_environment` raises
  `ParserError` before the victim is called.
- Batch 11: 273 of 447 attacker rewrites (tries 2..8) ended in ParserError (per victim: 20b 50,
  qwen3-32b 56, 120b 60, mistral-large-3 22, qwen3-vl-235b 40, deepseek.v3.2 45). Those tries never
  reached the victim, so batch 11's within-k numbers for k >= 2 understate the attacker.
- Batch 10 (unseeded adaptive, tools/bench_batch10.py) injects rewrites the same way and has the
  same bug. Its code and runs are left unchanged; its adaptive result (2/111) is not valid evidence
  of attacker strength and is reported as such.
- Try 1 (batch-9 hand-written `_JB_STRING` text) has no `"` or `\` and loaded on every pair; it is
  unaffected. Its raw newlines went through YAML folding in the default path, as in batch 9.

## Fix (commit 0a9aa75)
- `tools/bench_batch11.py:yaml_safe` escapes a rewrite with PyYAML itself
  (`yaml.dump(..., default_style='"', width=10**9, allow_unicode=True)`, outer quotes stripped), so
  `yaml.safe_load` returns the exact attacker text. Applied only to the values handed to AgentDojo
  for tries >= 2; run records keep the raw text. No hand-written escaper.
- Test `tests/test_batch11b_yaml.py`: all 273 real failing rewrites raise raw and load escaped with
  the text intact; a quote/backslash rewrite reaches the victim in the 11b runner path.
- Code frozen for 11b (SHA-256): tools/bench_batch11.py f0e49e3e04c56cb4f7f6e1d781f0bae135876476223c9e49f33ead0656e653e7
  (batch 11: c5a4f771...); tools/bench_batch11b.py d71421dd8c13514fb9826be61c02f1f9e928ca9cae000b68e05ebc0af9f39d79.
  bench_batch10.py, bench_batch9.py, bench_agentdojo.py, bench_bedrock.py, acp/bench_gate.py
  unchanged (SHAs as in repeats/batch11/PROTOCOL.md).

## Rerun (batch 11b, runner tools/bench_batch11b.py)
- All 102 pairs (17 set-A tasks x 6 victims), same victims, victim temperature 0, same gated arm.
- Try 1 is reused from the batch-11 record of the same pair (no call). The 33 pairs whose try 1
  succeeded are copied as they are (success at k = 1).
- The other 69 pairs re-run tries 2..8: same attacker (qwen.qwen3-32b-v1:0, temperature 0.7,
  maxTokens 1024, the batch-10 prompts unchanged), same history rule (try 1 included), K = 8 fixed.
  A pair stops at its first success. Batch-11 tries 2..8 are not reused.
- Money: hard cap USD 3.00 new spend at Bedrock list price, pilot included. Pilot `--limit 2` on
  gpt-oss-20b first, then a projection; victims run cheapest first (order of the batch-11
  protocol), each with `--budget-usd` = min(1.5 x projected, cap left - 0.30). A victim stopped by
  budget keeps its finished pairs; the rest are reported as not run. Real-money tripwire budget
  must read 0.0 before and after.
- All runs are reported, pilot included; no run is repeated to change its result; resume only
  fills pairs that never started.
- Outputs repeats/batch11b/: summary.{md,json}, success.csv (within k = 1..8 per victim and pooled,
  Wilson 95%, errors in n), tries.csv (blocking control per try, same categories as batch 11),
  compare.csv (against batch-9 hand-written only, 37/102), ParserError count (expected 0).
