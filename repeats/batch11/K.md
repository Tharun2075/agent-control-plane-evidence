# Batch 11 K decision (PROTOCOL.md rule, after the 2-pair pilot)

Pilot: `--limit 2 --max-tries 8` per victim (banking/user_task_3, banking/user_task_4); pilot runs count as data.

| victim | pilot runs | tries | cost $ | mean $ per try | projected $ (17 x 8 tries) | --budget-usd |
|---|---|---|---|---|---|---|
| qwen.qwen3-32b-v1:0 | 2 | 9 | 0.0076 | 0.00084 | 0.114 | 0.17 |
| openai.gpt-oss-20b-1:0 | 2 | 10 | 0.0094 | 0.00094 | 0.128 | 0.19 |
| openai.gpt-oss-120b-1:0 | 2 | 9 | 0.0090 | 0.00099 | 0.135 | 0.20 |
| qwen.qwen3-vl-235b-a22b | 2 | 9 | 0.0127 | 0.00142 | 0.193 | 0.29 |
| mistral.mistral-large-3-675b-instruct | 2 | 9 | 0.0249 | 0.00277 | 0.377 | 0.57 |
| deepseek.v3.2 | 2 | 9 | 0.0310 | 0.00344 | 0.468 | 0.70 |

P(8) = 1.414, P(6) = 1.061, P(5) = 0.884 (USD). P(8) <= 5.40, so K = 8 and no victim is dropped.
Pilot spend 0.095; cap left 5.905, so every budget is the 1.5 x projection (all below cap left - 0.30).
Run order as pre-registered: gpt-oss-20b, qwen3-32b, gpt-oss-120b, mistral, qwen3-vl, deepseek.
