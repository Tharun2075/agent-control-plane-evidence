PY ?= python3

.PHONY: reproduce test check verify repeats check-history batch6
reproduce:
	$(PY) -m acp reproduce

test:
	$(PY) -m unittest discover -s tests -t .

DENYLIST ?= ../denylist.txt

# Public-safe check: pattern scan of tracked files, plus the private deny-list
# (kept outside the repo) over the tree and the full history of main.
check: test
	$(PY) tools/public_safe_check.py $$( [ -f "$(DENYLIST)" ] && echo --denylist "$(DENYLIST)" )
	@$(MAKE) -s check-history DENYLIST="$(DENYLIST)"

# Deny-list scan of the tree, of main's full history and of the current branch's commits not on
# main (main..HEAD), so blobs replaced on a work branch are scanned too. No main branch means no history to
# scan: fail (exit 2) instead of reporting 0 hits over an empty log.
check-history:
	@if [ -f "$(DENYLIST)" ]; then \
	  git rev-parse --verify -q main >/dev/null || { echo "check: no main branch, history not scanned (Fix: git fetch origin main:main)"; exit 2; }; \
	  n=$$( { git ls-files -z | xargs -0 grep -I -F -f "$(DENYLIST)" -- ; git log -p main | grep -F -f "$(DENYLIST)"; git log -p main..HEAD | grep -F -f "$(DENYLIST)"; } | wc -l | tr -d ' '); \
	  echo "deny-list hits (tree + git log -p main + main..HEAD): $$n"; [ "$$n" = 0 ]; \
	else echo "deny-list $(DENYLIST) not found: skipped (pattern scan only)"; fi

# Re-aggregate repeats/ (runs 4-6 x 10) from the committed logs.
repeats:
	$(PY) -m acp repeats-summary

# Re-aggregate batch 6 (AgentDojo, repeats/batch6/PROTOCOL.md) from the committed run records.
batch6:
	$(PY) -m acp batch6-summary

# Re-verify every committed chain (scripted, model-driven and repeats/), recompute metrics
# from the committed logs and require them to equal the committed metrics.json.
verify:
	$(PY) -m acp verify-all
	@tmp=$$(mktemp -t acp-metrics.XXXXXX); \
	$(PY) -m acp metrics --out $$tmp && $(PY) tools/compare_metrics.py metrics.json $$tmp; rc=$$?; rm -f $$tmp; exit $$rc
	@tmp=$$(mktemp -t acp-repeats.XXXXXX); \
	$(PY) -m acp repeats-summary --out $$tmp && cmp -s repeats/summary.json $$tmp; rc=$$?; rm -f $$tmp; \
	if [ $$rc = 0 ]; then echo "repeats summary identical: True"; else echo "repeats summary identical: False"; fi; exit $$rc
	@$(PY) -c 'import json,sys; from pathlib import Path; from acp.repeats import tricks_markdown; \
	a = json.load(open("repeats/summary.json")); p = Path("repeats/batch4/tricks.md"); \
	ok = "batch4" not in a or (p.exists() and p.read_text() == tricks_markdown(a["batch4"])); \
	print("batch-4 tricks identical:", ok); sys.exit(0 if ok else 1)'
	@if [ -f repeats/batch6/summary.json ]; then \
	  tmp=$$(mktemp -d -t acp-b6.XXXXXX); $(PY) -m acp batch6-summary --out $$tmp; rc=0; \
	  for f in summary.json summary.md b1.csv b2.csv; do cmp -s repeats/batch6/$$f $$tmp/repeats/batch6/$$f || { echo "batch6 $$f differs"; rc=1; }; done; \
	  rm -rf $$tmp; echo "batch6 summary identical: $$( [ $$rc = 0 ] && echo True || echo False)"; \
	  [ $$rc = 0 ] && $(PY) tools/check_batch6.py; \
	else echo "batch6: no summary yet"; fi

# Batch 7 (AgentDojo on Bedrock, repeats/batch7/PROTOCOL.md): regenerate, compare, verify gate logs.
.PHONY: batch7 verify-batch7
batch7:
	$(PY) tools/batch7_summary.py
verify-batch7:
	$(PY) tools/batch7_summary.py --check
verify: verify-batch7

# Batch 8 (gate ablation and AgentDojo defences, repeats/batch8/PROTOCOL.md): regenerate, compare, verify gate logs.
.PHONY: batch8 verify-batch8
batch8:
	$(PY) tools/batch8_summary.py
verify-batch8:
	$(PY) tools/batch8_summary.py --check
verify: verify-batch8

# Batch 9 (AgentDojo defences, tool_knowledge, T=0.7 repeats, allowlist-aware attack, repeats/batch9/PROTOCOL.md).
.PHONY: batch9 verify-batch9
batch9:
	$(PY) tools/batch9_summary.py
verify-batch9:
	$(PY) tools/batch9_summary.py --check
verify: verify-batch9

# Batch 10 (outside AgentDojo attacks, adaptive LLM attacker, allowlist-off authority arm, repeats/batch10/PROTOCOL.md).
.PHONY: batch10 verify-batch10
batch10:
	$(PY) tools/batch10_summary.py
verify-batch10:
	$(PY) tools/batch10_summary.py --check
verify: verify-batch10

# Batch 11 (batch-10 attacker seeded with the batch-9 allowlist-aware injection, repeats/batch11/PROTOCOL.md).
.PHONY: batch11 verify-batch11
batch11:
	$(PY) tools/batch11_summary.py
verify-batch11:
	$(PY) tools/batch11_summary.py --check
verify: verify-batch11

# Batch 11b (batch 11 re-run after the YAML fix, repeats/batch11b/PROTOCOL-ADDENDUM.md).
.PHONY: batch11b verify-batch11b
batch11b:
	$(PY) tools/batch11b_summary.py
verify-batch11b:
	$(PY) tools/batch11b_summary.py --check
verify: verify-batch11b
