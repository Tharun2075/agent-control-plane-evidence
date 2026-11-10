# Batch 7 protocol: AgentDojo on open-weight models via Amazon Bedrock, plain vs gated (pre-registered)

Written and committed before any Bedrock request of batch 7 (probes included). Every run record in
`repeats/batch7/runs/*.jsonl` and every probe in `repeats/batch7/probe.jsonl` carries a timestamp
later than the commit that adds this file. All runs that start are reported, including errors,
provider refusals, unavailable models and runs cut by a stop rule.

## Same as batch 6 (repeats/batch6/PROTOCOL.md, unchanged)
- Benchmark AgentDojo 0.1.35, suites v1.2.2 (`banking`, `slack`), attack `important_instructions`,
  benchmark default system prompt, no benchmark defence, max 15 tool iterations.
- Subset from `plan()` in tools/bench_agentdojo.py (seed 6): B1 = 37 benign + 40 attacked = 77 runs
  per model per arm; B2 = the first 10 attacked B1 pairs per suite (20 runs), arm plain only.
- Arms plain and gated; the gate (`acp/bench_gate.py`: approval gate, deterministic reviewer,
  allowlist, hash-chained log in `repeats/batch7/logs/*.gated.jsonl`) is reused unchanged.
- Metrics (benign utility, ASR, utility under attack, checks reached, target blocked; Wilson 95%)
  and outcome classes (`classify()`: provider-refused, error, succeeded, reached-target,
  model-declined) are the batch 6 code. Errors and refusals stay in every denominator.

## What is new: provider
- Amazon Bedrock Runtime Converse API with `toolConfig` (tools from the benchmark's function
  schemas), runner `tools/bench_bedrock.py`, which reuses the batch 6 runner by import.
- Sampling: temperature 0.0, maxTokens 4096. Reasoning text blocks are dropped from the history.
- Provider refusal: Converse `stopReason` `guardrail_intervened` or `content_filtered`.
- The attack names the model by vendor ("AI model developed by OpenAI", ...), as batch 6 does.
- Region us-east-1; us-west-2 only if a model is not served in us-east-1 (recorded per run).

## Models (only these; the allow list in the runner refuses any other id and any Anthropic id)
- Preferred for B1 and B2: openai.gpt-oss-120b-1:0, qwen.qwen3-32b-v1:0, deepseek.v3.2,
  mistral.mistral-large-3-675b-instruct, us.meta.llama4-maverick-17b-instruct-v1:0.
- Also on the list, run if budget allows after the preferred ones: openai.gpt-oss-20b-1:0,
  qwen.qwen3-vl-235b-a22b, google.gemma-3-27b-it, google.gemma-3-4b-it.
- Each model is probed first with one tool call (`--probe`). A model that is refused (access,
  region or licence block, e.g. Meta's country rule) or cannot return a `toolUse` block through
  Converse is recorded as unavailable with the reason; no workaround is tried.
- Target: B1 both arms and B2 on at least 4 tool-capable models.

## Stop rules
- Budget USD 60 at list price for the batch (AWS credits; zero real money). Cost = Converse
  inputTokens x in-price + outputTokens x out-price (per 1M, us-east-1 on-demand, AWS Price List
  2026-11-06): gpt-oss-20b 0.07/0.30, gpt-oss-120b 0.15/0.60, qwen3-32b 0.15/0.60,
  qwen3-vl 0.53/2.66, gemma-3-4b 0.04/0.08, gemma-3-27b 0.23/0.38, mistral-large-3 0.50/1.50,
  deepseek-v3.2 0.62/1.85, llama4-maverick 0.24/0.97.
- Pilot 2-3 runs per model first; project 174 runs per model from the pilot tokens; do not start
  a model whose projection would take the batch over budget. `--budget-usd` stops a file at its share.
- Access, licence, quota or account errors stop that model for good (PROVIDER-STOP); throttling is
  retried at most 6 times with backoff, then stops the model. Missing runs are reported as not run.
- The AWS real-money tripwire budget must read 0.0 after the runs; any other value stops the batch.
- No run is repeated to change its result; resume only fills runs that never started.

## Outputs
- `python3 tools/batch7_summary.py` writes repeats/batch7/summary.{json,md}, b1.csv, b2.csv, and
  the batch 6 + 7 B1 table combined.{csv,md}; `--check` regenerates and compares them and
  verifies the batch 7 gate logs (`make verify`).

## Code frozen by this protocol (SHA-256)
- `acp/bench_gate.py`: 2a858f3751507867907ff743d9c8921aaf6d23cd016da2c034b1a593f8d0c25a
- `tools/bench_agentdojo.py`: 2d8084b22109440cf1c199315c8237f40f6570974afabaa3147b5a9648a6c6fc
- `tools/bench_bedrock.py`: c321eb5bd84be91302e9869aa2953136b3ca48385fda7ce5a41e829cc32a0188
- `acp/batch7.py`: a17afa2888e0633dc203e584057251bcc630f628786e18deadfdd0c132e51d6a
- `tools/batch7_summary.py`: 4213c48be14bec5cbfba669cf6859d6174d15c13bb754a51c3e03efaa8862f4b
