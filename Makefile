PY ?= python3

.PHONY: reproduce test check verify
reproduce:
	$(PY) -m acp reproduce

test:
	$(PY) -m unittest discover -s tests -t .

check: test
	$(PY) tools/public_safe_check.py

# Re-verify every committed chain (scripted + model-driven), recompute metrics
# from the committed logs and require them to equal the committed metrics.json.
verify:
	$(PY) -m acp verify-all
	@tmp=$$(mktemp -t acp-metrics.XXXXXX); \
	$(PY) -m acp metrics --out $$tmp && $(PY) tools/compare_metrics.py metrics.json $$tmp; rc=$$?; rm -f $$tmp; exit $$rc
