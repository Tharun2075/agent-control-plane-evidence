#!/usr/bin/env bash
# Batch-19 main run (repeats/batch19/PROTOCOL.md): one process per victim in parallel, --workers 4,
# per-model cap USD 3, resume from the JSONL in repeats/batch19/runs. Usage: run-all.sh [--dry-run]
# The runner retries with adaptive backoff and refuses unless PROTOCOL and code hashes are committed.
set -euo pipefail
cd "$(dirname "$0")/../.."
PY=../bedrock-venv/bin/python
DRY=""; [ "${1:-}" = "--dry-run" ] && DRY="--dry-run"
MODELS=(openai.gpt-oss-20b-1:0 openai.gpt-oss-120b-1:0 qwen.qwen3-32b-v1:0
        qwen.qwen3-vl-235b-a22b mistral.mistral-large-3-675b-instruct deepseek.v3.2)
A=~/.workflow/bin/aws-thatched; ACC=952267027727
trip() { "$A" budgets describe-budgets --account-id "$ACC" \
  --query "Budgets[?BudgetName=='thatched-real-money-tripwire'].CalculatedSpend.ActualSpend.Amount" --output text; }
T=$(trip); echo "tripwire before: $T"
case "$T" in 0|0.0|0.00) ;; *) echo "STOP: tripwire reads $T"; exit 3;; esac
K="${AWS_BEDROCK_KEY_ID:?set AWS_BEDROCK_KEY_ID to the Bedrock access key id}"
export AWS_ACCESS_KEY_ID=$K AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null
AWS_SECRET_ACCESS_KEY="$(~/.workflow/bin/secret-get aws-thatched-bedrock "$K")"; export AWS_SECRET_ACCESS_KEY
mkdir -p repeats/batch19/logs/runs
pids=()
for m in "${MODELS[@]}"; do
  f=repeats/batch19/logs/runs/${m//:/_}.run.out
  $PY tools/bench_batch19.py --model "$m" --workers 4 --budget-usd 3 $DRY >"$f" 2>&1 &
  pids+=($!)
done
unset AWS_SECRET_ACCESS_KEY
st() { for m in "${MODELS[@]}"; do printf '%-40s %s\n' "$m" "$(tail -n1 "repeats/batch19/logs/runs/${m//:/_}.run.out" 2>/dev/null)"; done; }
while [ -n "$(jobs -rp)" ]; do sleep 30; echo "--- $(date -u +%H:%M:%SZ)"; st; done
rc=0; for p in "${pids[@]}"; do wait "$p" || rc=1; done
echo "--- done rc=$rc"; st
[ -n "$DRY" ] && exit $rc
$PY tools/batch19_summary.py --dir runs >/dev/null && echo "summary: repeats/batch19/runs-summary.md"
echo "tripwire after: $(trip)"
exit $rc
