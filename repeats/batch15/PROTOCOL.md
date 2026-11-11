# Batch 15 protocol: gpt-oss-120b B1 plain + gated after the empty-key toolUse.input fix (pre-registered)

Written and committed before any model request of batch 15 (probes and pilots included). Every
run record in `repeats/batch15/runs/*.jsonl` and every probe in `repeats/batch15/probe.jsonl`
carries a timestamp later than the commit that adds this file. All runs that start are reported,
including errors, provider refusals and runs cut by a stop rule.

## Question
Batch 14 left 4 errors on gpt-oss-120b gated B1 (v1.2: 3), all Bedrock `ValidationException`
"messages.1.content.0.toolUse.input is invalid". Cause (reproduced 2026-11-11): gpt-oss-120b answers
a no-argument tool call with toolUse.input `{"": {}}`; our Converse adapter replayed it verbatim and
Bedrock refuses an empty-string key at any depth. Fix a3e1ead (tools/bench_bedrock.py `as_object` drops
empty-string keys recursively; test tests/test_bedrock_toolinput.py replays all 84 recorded cases
offline). Does the fix remove these errors, and do ASR and utility of gpt-oss-120b change?

## Same as batches 7 and 14 (repeats/batch7/PROTOCOL.md, repeats/batch14/PROTOCOL.md)
- AgentDojo 0.1.35, suites v1.2.2 (`banking`, `slack`), attack `important_instructions`, default
  system prompt, no benchmark defence, max 15 tool iterations.
- Subset B1 from `plan()` in tools/bench_agentdojo.py (seed 6): 37 benign + 40 attacked = 77 runs
  per arm, the same tasks and pairs as batches 7 and 14.
- Bedrock Converse us-east-1, temperature 0.0, maxTokens 4096. Gate as in batch 14 (paper-fix12),
  per-call `chk` verdicts recorded as in batch 14.
- Outcome classes (`classify()`), Wilson 95% intervals, refusal rules unchanged. Errors and refusals
  stay in every denominator of the headline rates.

## Runs (one pass each, B1 only)
- openai.gpt-oss-120b-1:0, plain arm and gated arm, 77 + 77 runs.
- Runner: `tools/bench_batch15.py` = the batch 14 wrapper pointed at repeats/batch15/; it refuses
  any other model or provider. Never an Anthropic model on Bedrock.

## Comparison (tools/batch15_summary.py)
- Rows `v1.2-plain` / `v1.2-gated` (batch 7), `b14-gated` (batch 14), `b15-plain` / `b15-gated`:
  ASR k/40 with Wilson CI, benign utility k/37, utility under attack, errors, provider refusals.
- Errors by class per arm, with the count of toolUse.input ValidationExceptions.
- Sensitivity line only: ASR with errored attacked runs removed from the denominator.

## Stop rules (money)
- Bedrock (AWS credits): hard cap USD 1 for the batch; per-file `--budget-usd 0.3`.
- The AWS real-money tripwire budget must read 0.0 before and after; any other value stops the batch.
- Pilot 2 runs per file first. Access, quota or account errors stop the batch (reported as not run).
- No run is repeated to change its result; resume only fills runs that never started.

## Outputs
- `python3 tools/batch15_summary.py` writes repeats/batch15/summary.{json,md,csv}, errors.csv,
  sensitivity.csv; `--check` regenerates, compares and verifies the batch 15 gate logs (`make verify`).

## Code frozen by this protocol (SHA-256; also repeats/batch15/code-sha256.json)

- `acp/batch14.py`: 47e1655027aea608dd793ad7d6fd582fac9653e720f2d37f5d4d7cd05d08e9c7
- `acp/batch15.py`: 371a4dfd4c538cae578c764be647dc8d78afafcd8e1407850cebbc26ebfca682
- `acp/batch8_gate.py`: 9981e68c14accae7ca766882b9bb44689bfac360a5a3e57bd9ba0334c43772b1
- `acp/bench_gate.py`: 5721d1d185e0f2cc43d97a7c6d8be94fcecb94d7865ce791d25f237f417a65c3
- `acp/gate.py`: a4387433b5bb6f691d42169c2ac60ffe79f1ebf072c16bf2428be5e70efa4904
- `tools/batch15_summary.py`: 4ff6756476b760a9a77f84954deaeed142ce6f75f521343e761f67148dbe49e8
- `tools/bench_agentdojo.py`: 2d8084b22109440cf1c199315c8237f40f6570974afabaa3147b5a9648a6c6fc
- `tools/bench_batch15.py`: 513abb44cab7bb43ba4c2313bbfb1bea42215d5be53094651cbe942b724df249
- `tools/bench_bedrock.py`: 20ba6e4cba7d826a10dfa99123c620d0613c3091ab8a22a258fb18ea89223068
