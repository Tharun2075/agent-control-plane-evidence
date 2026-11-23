#!/usr/bin/env bash
# Batch-20 arm a (repeats/batch20a/PROTOCOL.md): Progent arm extended (a2 adaptive pairs, a3 outside
# attacks, a4 policy-model slice). One process per victim (a2 then a3), one more for a4; --workers 4;
# per-model caps in USD (CAP2/CAP3/CAP4 below, from the pilot projection); resume from the JSONL.
# Usage: run-all.sh [--dry-run|--pilot]. Status: repeats/batch20a/logs/status.txt
# Key id and account id are read at run time (env or the runbook), never stored here.
set -euo pipefail
cd "$(dirname "$0")/../.."
PY=../bedrock-venv/bin/python
MODE=main; [ "${1:-}" = "--dry-run" ] && MODE=dry; [ "${1:-}" = "--pilot" ] && MODE=pilot
MODELS=(openai.gpt-oss-20b-1:0 openai.gpt-oss-120b-1:0 qwen.qwen3-32b-v1:0
        qwen.qwen3-vl-235b-a22b mistral.mistral-large-3-675b-instruct deepseek.v3.2)
cap() {  # cap <set> <model>: USD per model and set (bash 3.2 has no associative arrays)
  case "$1:$2" in
    a2:qwen.qwen3-vl-235b-a22b) echo 0.35;; a2:deepseek.v3.2) echo 0.45;; a2:*) echo 0.25;;
    a3:openai.gpt-oss-20b-1:0|a3:openai.gpt-oss-120b-1:0) echo 1.45;; a3:qwen.qwen3-32b-v1:0) echo 1.35;;
    a3:qwen.qwen3-vl-235b-a22b) echo 2.50;; a3:mistral.mistral-large-3-675b-instruct) echo 1.50;;
    a3:deepseek.v3.2) echo 3.40;; *) echo 0;;
  esac; }
CAP4=0.75; POL4=mistral.mistral-large-3-675b-instruct
RB=~/.workflow/runbooks/aws-thatched-bedrock.md
A=~/.workflow/bin/aws-thatched
ACC="${AWS_ACCOUNT_ID:-$(grep -oE 'acct [0-9]{12}' "$RB" | head -1 | awk '{print $2}')}"
K="${AWS_BEDROCK_KEY_ID:-$(grep -oE 'AKIA[A-Z0-9]{16}' "$RB" | head -1)}"
trip() { "$A" budgets describe-budgets --account-id "$ACC" \
  --query "Budgets[?BudgetName=='thatched-real-money-tripwire'].CalculatedSpend.ActualSpend.Amount" --output text; }
L=repeats/batch20a/logs; mkdir -p "$L/runs" "$L/pilot"
if [ "$MODE" != dry ]; then
  T=$(trip); echo "tripwire before: $T $(date -u +%FT%TZ)" | tee -a "$L/tripwire.log"
  case "$T" in 0|0.0|0.00) ;; *) echo "STOP: tripwire reads $T"; exit 3;; esac
  export AWS_ACCESS_KEY_ID=$K AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null
  AWS_SECRET_ACCESS_KEY="$(~/.workflow/bin/secret-get aws-thatched-bedrock "$K")"; export AWS_SECRET_ACCESS_KEY
fi
OUT=repeats/batch20a/runs; EXTRA=(--workers 4); D="$L/runs"
[ "$MODE" = pilot ] && { OUT=repeats/batch20a/pilot; EXTRA=(--workers 4 --limit 2); D="$L/pilot"; }
[ "$MODE" = dry ] && EXTRA=(--workers 4 --dry-run)
R() { $PY tools/bench_batch20a.py --out-dir "$OUT" "${EXTRA[@]}" "$@"; }
pids=()
for m in "${MODELS[@]}"; do
  f=$D/${m//:/_}.run.out
  ( R --model "$m" --set a2 --budget-usd "$(cap a2 "$m")" && R --model "$m" --set a3 --budget-usd "$(cap a3 "$m")" ) >"$f" 2>&1 &
  pids+=($!)
done
R --model openai.gpt-oss-20b-1:0 --set a4 --policy-model "$POL4" --budget-usd "$CAP4" >"$D/a4.run.out" 2>&1 &
pids+=($!)
unset AWS_SECRET_ACCESS_KEY
st() { echo "--- $(date -u +%FT%TZ) mode=$MODE"; for f in "$D"/*.run.out; do printf '%-48s %s\n' "$(basename "$f")" "$(tail -n1 "$f" 2>/dev/null)"; done; }
while [ -n "$(jobs -rp)" ]; do sleep 30; st >"$L/status.txt"; done
rc=0; for p in "${pids[@]}"; do wait "$p" || rc=1; done
st >"$L/status.txt"; echo "--- done rc=$rc" >>"$L/status.txt"; cat "$L/status.txt"
[ "$MODE" = dry ] && exit $rc
echo "tripwire after: $(trip) $(date -u +%FT%TZ)" | tee -a "$L/tripwire.log"
[ "$MODE" = main ] && $PY tools/batch20a_summary.py >/dev/null && echo "summary: repeats/batch20a/a-summary.md"
exit $rc
