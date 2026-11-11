"""Batch 14 runner: AgentDojo B1 at the paper-fix12 gate (no-recipient policy, signed approvals).

Thin wrapper over the batch 6 (Anthropic) and batch 7 (Bedrock) runners, unchanged by import:
it only points their output at repeats/batch14/ and records, on every gated tool call, each
control's own verdict (`chk`: action word, allowlist/task target) next to the enforced one.
Protocol: repeats/batch14/PROTOCOL.md.

  python tools/bench_batch14.py --provider anthropic --model claude-haiku-5-5 --arm gated --set B1
  python tools/bench_batch14.py --provider bedrock --model openai.gpt-oss-20b-1:0 --arm plain --set B1

Keys come from the environment only, as in the wrapped runners.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import bench_agentdojo as B  # noqa: E402
from acp import batch8_gate as G8, bench_gate  # noqa: E402

OUT = ROOT / "repeats" / "batch14"
B.RUN_DIR, B.LOG_DIR = OUT / "runs", OUT / "logs"


class Gated14(B.GatedToolsExecutor):
    """The batch 6 executor; adds each control's verdict to the call it just logged."""

    def _gate(self, fn: str, args: dict) -> str | None:
        denied = super()._gate(fn, args)
        st = self.st
        if fn in bench_gate.GATED[st.suite]:
            st.calls[-1]["chk"] = {
                "action": G8.review_approval(st.suite, fn, args, st.user_prompt)[0],
                "allowlist": G8.review_allowlist(st.suite, fn, args, st.user_prompt)[0]}
        return denied


B.GatedToolsExecutor = Gated14


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    provider = "anthropic"
    if "--provider" in argv:
        i = argv.index("--provider")
        provider = argv[i + 1]
        del argv[i:i + 2]
    if provider == "bedrock":
        import bench_bedrock as BB
        BB.RUN_DIR, BB.LOG_DIR, BB.PROBE_FILE = OUT / "runs", OUT / "logs", OUT / "probe.jsonl"
        return BB.main(argv)
    if provider != "anthropic":
        raise SystemExit("batch 14 runs Anthropic API or Bedrock only")
    return B.main(["--provider", "anthropic", *argv])


if __name__ == "__main__":
    raise SystemExit(main())
