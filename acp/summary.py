"""B1c: post-task summary from a chained log (Markdown + JSON).

Answers, for a person or a reviewer: what the agent(s) did, which personal
data categories were touched and on what lawful basis, which tools were used,
where data went (recipients), which steps needed human approval, what was
blocked or refused, and the result. The summary cites the log head hash, so it
can be checked against the log it came from.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from .log import read_records, verify


def summarize(log_path) -> dict:
    log_path = Path(log_path)
    recs = read_records(log_path)
    v = verify(log_path)
    agents: dict[str, dict] = {}
    for r in recs:
        a = agents.setdefault(r["gen_ai.agent.id"], {"manifest_sha256": set(), "sessions": set(), "steps": 0})
        a["manifest_sha256"].add(r["agent_manifest_sha256"])
        a["sessions"].add(r["gen_ai.conversation.id"])
        a["steps"] += 1
    tools = Counter(r["gen_ai.tool.name"] for r in recs if r["gen_ai.tool.name"])
    cats = sorted({c for r in recs for c in r["personal_data_categories"] if c != "none"})
    bases = Counter(r["lawful_basis"] for r in recs)
    sent, intended = [], []
    for r in recs:
        for rcpt in r["recipients"]:
            item = {"recipient": rcpt, "agent": r["gen_ai.agent.id"], "seq": r["seq"], "action": r["action"],
                    "personal_data_categories": r["personal_data_categories"]}
            (sent if r["outcome"] == "ok" else intended).append(item)
    gated = [r for r in recs if r["detail"].get("gate") in ("approved", "blocked", "rejected")]
    approvals = [
        {"seq": r["seq"], "tool": r["gen_ai.tool.name"], "action": r["action"], "gate": r["detail"]["gate"],
         "approver": r["detail"].get("approver"), "simulated": r["detail"].get("approval_simulated")}
        for r in gated
    ]
    refusals = [
        {"seq": r["seq"], "agent": r["gen_ai.agent.id"], "action": r["action"], "outcome": r["outcome"],
         "probe": bool(r["detail"].get("probe"))}
        for r in recs if r["outcome"].startswith("refused")
    ]
    unclear = [
        {"seq": r["seq"], "action": r["action"], "reason": r["detail"].get("lawful_basis_reason", "")}
        for r in recs if r["lawful_basis"] == "unclear"
    ]
    ends = [r for r in recs if r["action"] == "task_end"]
    task = next((r["detail"].get("task") for r in recs if r["action"] == "task_start"), "")
    return {
        "log": log_path.name,
        "log_verified": v.ok,
        "log_records": v.records,
        "log_head_hash": v.last_hash,
        "task": task,
        "agents": {k: {"manifest_sha256": sorted(a["manifest_sha256"]), "sessions": sorted(a["sessions"]),
                       "steps": a["steps"]} for k, a in agents.items()},
        "steps": len(recs),
        "tools_used": dict(sorted(tools.items())),
        "personal_data_categories": cats,
        "lawful_basis_tags": dict(sorted(bases.items())),
        "lawful_basis_unclear": unclear,
        "recipients_data_sent_to": sent,
        "recipients_blocked_not_sent": intended,
        "approvals": approvals,
        "refusals": refusals,
        "outcome": [{"agent": r["gen_ai.agent.id"], "outcome": r["outcome"], "result": r["detail"].get("result", "")}
                    for r in ends],
    }


def to_markdown(s: dict) -> str:
    L = [f"# Post-task summary: {s['task']}", ""]
    L.append(f"Log `{s['log']}`: {s['log_records']} records, chain verified: **{'yes' if s['log_verified'] else 'NO'}**, "
             f"head hash `{s['log_head_hash'][:16]}…`")
    L += ["", "## Who acted"]
    for aid, a in s["agents"].items():
        L.append(f"- `{aid}`: {a['steps']} steps, session(s) {', '.join(a['sessions'])}, "
                 f"identity digest {', '.join(d[:19] + '…' for d in a['manifest_sha256'])}")
    L += ["", "## What it did", f"- {s['steps']} logged steps",
          "- Tools: " + (", ".join(f"{k} ×{v}" for k, v in s["tools_used"].items()) or "none")]
    L += ["", "## Personal information used",
          "- Categories: " + (", ".join(s["personal_data_categories"]) or "none"),
          "- Lawful-basis tags: " + ", ".join(f"{k} ×{v}" for k, v in s["lawful_basis_tags"].items())]
    for u in s["lawful_basis_unclear"]:
        L.append(f"  - unclear at record {u['seq']} ({u['action']}): {u['reason']}")
    L += ["", "## Where data went"]
    if not s["recipients_data_sent_to"]:
        L.append("- No data left the agent's own session.")
    for x in s["recipients_data_sent_to"]:
        L.append(f"- {x['recipient']} (record {x['seq']}, {x['action']}; {', '.join(x['personal_data_categories'])})")
    for x in s["recipients_blocked_not_sent"]:
        L.append(f"- NOT SENT, blocked: {x['recipient']} (record {x['seq']}, {x['action']})")
    L += ["", "## Approvals and human involvement"]
    if not s["approvals"]:
        L.append("- No step required approval.")
    for a in s["approvals"]:
        who = f" by {a['approver']}" + (" (simulated reviewer)" if a["simulated"] else "") if a["approver"] else ""
        L.append(f"- record {a['seq']}: {a['tool']} / {a['action']}: {a['gate']}{who}")
    L += ["", "## Refused or blocked by controls"]
    if not s["refusals"]:
        L.append("- None.")
    for r in s["refusals"]:
        L.append(f"- record {r['seq']}: {r['agent']} {r['action']}: {r['outcome']}"
                 + (" (deliberate test probe)" if r["probe"] else ""))
    L += ["", "## Result"]
    for o in s["outcome"]:
        L.append(f"- {o['agent']}: {o['outcome']}. {o['result']}")
    L += ["", "## How to challenge or correct",
          "- Each line above cites a log record number; the record holds the agent identity digest, inputs' "
          "content hashes and the decision mode, so a person can ask for that specific step to be reviewed, "
          "corrected or reversed."]
    return "\n".join(L) + "\n"
