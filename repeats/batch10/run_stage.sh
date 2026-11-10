#!/bin/bash
# Batch 10 driver: one background job per model, each running its (arm, attack) files in order.
# Usage: run_stage.sh <stage-name> <budget-per-file> <limit> "<arms>" "<attacks>" <model>...
# Expects the Bedrock key in the environment only (never on disk); see PROTOCOL.md.
set -u
cd "$(dirname "$0")/../.."
PY=${PY:-/Users/thar/.workflow/scratch/ico-evidence/bedrock-venv/bin/python}
stage=$1; budget=$2; limit=$3; arms=$4; attacks=$5; shift 5
mkdir -p repeats/batch10/logs
for m in "$@"; do
  (
    for arm in $arms; do
      for att in $attacks; do
        tag=${m//[:\/]/_}
        log=repeats/batch10/logs/${tag}__${arm}__${att}__T0.log
        $PY tools/bench_batch10.py --model "$m" --arm "$arm" --attack "$att" --limit "$limit" \
          --budget-usd "$budget" --workers 4 >> "$log" 2>&1
        echo "$stage $m $arm $att: $(tail -1 "$log")"
      done
    done
  ) &
done
wait
