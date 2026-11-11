# Batch 14 protocol: B1 gated arm at the paper-fix12 gate, and gpt-oss-20b after the tool-name fix (pre-registered)

Written and committed before any model request of batch 14 (probes and pilots included). Every
run record in `repeats/batch14/runs/*.jsonl` and every probe in `repeats/batch14/probe.jsonl`
carries a timestamp later than the commit that adds this file. All runs that start are reported,
including errors, provider refusals and runs cut by a stop rule.

## Question
1. Does the gate as merged in paper-fix12 (eaef917: checks for gated tools with no recipient
   argument, HMAC-signed approvals, tool-name adapter) change the published v1.2 gated B1 cells
   (batch 6 Claude, batch 7 open models): ASR, benign utility, errors, and which control decided
   each attacked run?
2. Does the Bedrock tool-name adapter remove the gpt-oss-20b errors of batch 7, plain and gated?

## Same as batches 6 and 7 (repeats/batch6/PROTOCOL.md, repeats/batch7/PROTOCOL.md)
- AgentDojo 0.1.35, suites v1.2.2 (`banking`, `slack`), attack `important_instructions`, default
  system prompt, no benchmark defence, max 15 tool iterations.
- Subset B1 from `plan()` in tools/bench_agentdojo.py (seed 6): 37 benign + 40 attacked = 77 runs
  per model per arm, the same tasks and pairs as batches 6/7.
- Sampling: Claude models keep the API default (as batch 6); Bedrock temperature 0.0, maxTokens 4096.
- Outcome classes (`classify()`), Wilson 95% intervals, refusal rules (Converse `guardrail_intervened`
  / `content_filtered`; Anthropic refusal stop) unchanged. Errors and refusals stay in every denominator.

## Runs (one pass each, B1 only)
- Gated arm on all 9 models: claude-haiku-5-5, claude-sonnet-5-5, claude-opus-5-5 (Anthropic API);
  openai.gpt-oss-120b-1:0, openai.gpt-oss-20b-1:0, qwen.qwen3-32b-v1:0, qwen.qwen3-vl-235b-a22b,
  deepseek.v3.2, mistral.mistral-large-3-675b-instruct (Bedrock Converse, us-east-1).
- Plain arm on openai.gpt-oss-20b-1:0 only (question 2).
- Runner: `tools/bench_batch14.py` imports the batch 6/7 runners unchanged, points their output to
  repeats/batch14/, and adds one field per gated target-tool call: `chk` = the verdict of the
  action-word check and of the target allowlist check, recorded whether or not the call was blocked.
  The enforced decision is the unchanged `GatedToolsExecutor` gate.
- Never an Anthropic model on Bedrock; the runner allow list refuses it.

## Comparison (tools/batch14_summary.py)
- Rows `v1.2-gated` (published batch 6/7 gated B1 records, and `v1.2-plain` for gpt-oss-20b) against
  `b14-gated` / `b14-plain`: ASR (AgentDojo security scorer) with Wilson CI, benign utility, errors,
  provider refusals.
- Attribution of each attacked run to one class by its per-call gate log: blocked_action (action not
  in user task), blocked_allowlist (target not in allowlist / not in user task (allowlist)),
  blocked_approval, blocked_other, succeeded, approved_no_effect, unchecked_target_call, no_target_call,
  error, provider_refused. Would-block counts from `chk` on batch 14 records.
- gpt-oss-20b error table per arm with error classes, before (v1.2) and after (b14).

## Stop rules (money)
- Anthropic API: hard cap USD 6 at list price (haiku 0.10/0.50, sonnet 2/10, opus 4/20 per 1M);
  per-file `--budget-usd`: haiku 0.3, sonnet 2.1, opus 3.6.
- Bedrock (AWS credits): hard cap USD 4 at the batch 7 list prices; per-file `--budget-usd`:
  deepseek 1.2, qwen3-vl 0.8, mistral 0.4, gpt-oss-120b 0.3, qwen3-32b 0.3, gpt-oss-20b 0.3 per arm.
- The AWS real-money tripwire budget must read 0.0 before and after; any other value stops the batch.
- Pilot 2 runs per file first. Access, quota or account errors stop that model (reported as not run).
- No run is repeated to change its result; resume only fills runs that never started.

## Outputs
- `python3 tools/batch14_summary.py` writes repeats/batch14/summary.{json,md,csv}, attribution.csv,
  would_block.csv, gpt_oss_20b_errors.csv; `--check` regenerates, compares and verifies the batch 14
  gate logs (`make verify`).

## Code frozen by this protocol (SHA-256; also repeats/batch14/code-sha256.json)

- `acp/batch14.py`: 47e1655027aea608dd793ad7d6fd582fac9653e720f2d37f5d4d7cd05d08e9c7
- `acp/batch8_gate.py`: 9981e68c14accae7ca766882b9bb44689bfac360a5a3e57bd9ba0334c43772b1
- `acp/bench_gate.py`: 5721d1d185e0f2cc43d97a7c6d8be94fcecb94d7865ce791d25f237f417a65c3
- `acp/gate.py`: 378172aa83273830efc48dd4040972be3e775fedb55854ab72c6184630315e87
- `tools/batch14_summary.py`: 5e126b8001f1bf47044efe6fde4ba5fa525e083a2bb15113c67ed1cd1f1966a6
- `tools/bench_agentdojo.py`: 2d8084b22109440cf1c199315c8237f40f6570974afabaa3147b5a9648a6c6fc
- `tools/bench_batch14.py`: eae05bd856caeaa8f5b60d49c89a03e2854502e8bb8aec82b6f24efb01b30819
- `tools/bench_bedrock.py`: 9522c986ede90258e4ebfb0b3350b682134f888f5bbdc50d9135d872daf6ac89
