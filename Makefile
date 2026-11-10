PY ?= python3

.PHONY: reproduce test check verify repeats
reproduce:
	$(PY) -m acp reproduce

test:
	$(PY) -m unittest discover -s tests -t .

DENYLIST ?= ../denylist.txt

# Public-safe check: pattern scan of tracked files, plus the private deny-list
# (kept outside the repo) over the tree and the full history of main.
check: test
	$(PY) tools/public_safe_check.py $$( [ -f "$(DENYLIST)" ] && echo --denylist "$(DENYLIST)" )
	@if [ -f "$(DENYLIST)" ]; then \
	  n=$$( { git ls-files -z | xargs -0 grep -I -F -f "$(DENYLIST)" -- ; git log -p main | grep -F -f "$(DENYLIST)"; } | wc -l | tr -d ' '); \
	  echo "deny-list hits (tree + git log -p main): $$n"; [ "$$n" = 0 ]; \
	else echo "deny-list $(DENYLIST) not found: skipped (pattern scan only)"; fi

# Re-aggregate repeats/ (runs 4-6 x 10) from the committed logs.
repeats:
	$(PY) -m acp repeats-summary

# Re-verify every committed chain (scripted, model-driven and repeats/), recompute metrics
# from the committed logs and require them to equal the committed metrics.json.
verify:
	$(PY) -m acp verify-all
	@tmp=$$(mktemp -t acp-metrics.XXXXXX); \
	$(PY) -m acp metrics --out $$tmp && $(PY) tools/compare_metrics.py metrics.json $$tmp; rc=$$?; rm -f $$tmp; exit $$rc
	@tmp=$$(mktemp -t acp-repeats.XXXXXX); \
	$(PY) -m acp repeats-summary --out $$tmp && cmp -s repeats/summary.json $$tmp; rc=$$?; rm -f $$tmp; \
	if [ $$rc = 0 ]; then echo "repeats summary identical: True"; else echo "repeats summary identical: False"; fi; exit $$rc
