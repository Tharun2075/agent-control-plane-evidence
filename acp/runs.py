"""B2: three reference tasks run through the library.

The agents are scripted (deterministic Python, no model call), so a clean
checkout reproduces every log byte for byte. Data: one public Companies House
page (snapshot, OGL v3.0) and synthetic records only.

Records marked detail.probe = true are deliberate control tests, not
something the task needed; metrics count them separately.
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from .agent import AgentContext
from .canon import digest, file_digest
from .gate import ApprovalRequired, PermissionDenied, ToolRunner, write_approval
from .isolation import IsolationError, SessionStore
from .log import ChainLog, FixedStepClock
from .manifest import bind_session, load, write

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
PHONE_RE = re.compile(r"(?:\+44|\b0)\d[\d ]{8,12}\d")


def _setup(root: Path, out: Path, start: str):
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    return ChainLog(out / "log.jsonl", clock=FixedStepClock(start))


def _agent(root, out, log, name, sid, task, **kw):
    m = bind_session(load(root / "manifests" / f"{name}.json"), session_id=sid, task=task,
                     expires="2026-11-10T23:59:59Z", **kw)
    write(m, out / "manifests" / f"{name}.json")
    ctx = AgentContext(log, m, sid)
    return ctx, ToolRunner(ctx, out / "approvals"), SessionStore(out / "sessions", ctx)


# ---------------------------------------------------------------- run 1
def run1(root: Path, out: Path) -> str:
    """Research: summarise a public company page."""
    log = _setup(root, out, "2026-11-10T09:00:00Z")
    num = "02557590"
    task = f"Summarise the public Companies House overview of company {num} for internal research"
    ctx, tr, store = _agent(root, out, log, "research-agent", "run1-research-s1", task)
    ctx.record(operation="invoke_agent", action="task_start", outcome="ok", detail={"task": task})
    snap = root / "data" / "public" / f"companies-house-{num}.txt"
    meta = json.loads((root / "data" / "public" / f"companies-house-{num}.meta.json").read_text())
    text = tr.call(
        "http_get", "fetch_public_page",
        lambda: (snap.read_text(encoding="utf-8"),
                 {"source": meta["source_url"], "retrieved_at": meta["retrieved_at"],
                  "raw_html_sha256": meta["raw_html_sha256"], "content_sha256": file_digest(snap),
                  "licence": "OGL-3.0", "replayed_from": f"data/public/{snap.name}"}),
        payload={"url": meta["source_url"]}, detail={"url": meta["source_url"]})

    def extract():
        lines = text.splitlines()
        labels = ["Registered office address", "Company status", "Company type", "Incorporated on",
                  "Nature of business (SIC)"]
        facts = {lab: lines[lines.index(lab) + 1] for lab in labels if lab in lines}
        i = lines.index("Period") if "Period" in lines else len(lines)
        facts["Previous company names"] = [l for l in lines[i + 1:] if l.isupper()]
        found = {"emails": len(EMAIL_RE.findall(text)), "phone_numbers": len(PHONE_RE.findall(text))}
        return facts, {"derived_from": file_digest(snap), "content_sha256": digest(facts)}, \
            {"detail": {"personal_data_scan": found}}

    facts = tr.call("html_extract", "extract_company_facts", extract)
    # The scripted planner proposes reading the officers page ("who runs it?").
    # The manifest's purpose excludes officer personal data, so the gate refuses.
    officers = [l for l in meta["links_on_page"] if l.endswith("/officers")]
    for link in officers:
        url = "https://find-and-update.company-information.service.gov.uk" + link
        try:
            tr.call("http_get", "follow_link", lambda: (None, None), payload={"url": url},
                    detail={"planner_reason": "find who runs the company",
                            "would_touch": ["identifier:name (company officers, public register)"]})
        except PermissionDenied:
            pass
    md = [f"# Company summary: {num}", "", f"Source: {meta['source_url']} (retrieved {meta['retrieved_at']}, "
          "Crown copyright, OGL v3.0)", ""]
    for k, v in facts.items():
        md.append(f"- {k}: {', '.join(v) if isinstance(v, list) else v}")
    md.append("- Officers: not collected (outside the stated purpose)")
    store.write("company-summary.md", "\n".join(md) + "\n", derived_from=digest(facts))
    ctx.record(operation="invoke_agent", action="task_end", outcome="ok",
               detail={"result": "company summary written to session; no personal data collected"})
    return task


# ---------------------------------------------------------------- run 2
def run2(root: Path, out: Path) -> str:
    """Outreach: draft an email to a synthetic contact; the send hits the gate."""
    log = _setup(root, out, "2026-11-10T10:00:00Z")
    task = "Draft a first-contact business email to synthetic contact c-001; do not send without approval"
    ctx, tr, store = _agent(root, out, log, "outreach-agent", "run2-outreach-s1", task)
    ctx.record(operation="invoke_agent", action="task_start", outcome="ok", detail={"task": task})
    src = root / "data" / "synthetic" / "contacts.json"
    cats = ["identifier:name", "professional:job_title", "professional:employer"]
    li = "Art 6(1)(f): business-to-business contact research for the purpose in the manifest"
    contact = tr.call(
        "crm_read", "read_contact",
        lambda: (next(c for c in json.loads(src.read_text())["contacts"] if c["contact_id"] == "c-001"),
                 {"source": "data/synthetic/contacts.json", "content_sha256": file_digest(src),
                  "record": "c-001", "synthetic": True}),
        payload={"contact_id": "c-001"}, personal_data_categories=cats, lawful_basis="legitimate_interests",
        detail={"lawful_basis_reason": li})
    tpl = root / "data" / "templates" / "intro-email.txt"
    draft = tr.call(
        "template_render", "render_email",
        lambda: (tpl.read_text().format(**contact),
                 {"source": "data/templates/intro-email.txt", "content_sha256": file_digest(tpl)}),
        payload={"template": "intro-email", "contact_id": "c-001"},
        personal_data_categories=cats, lawful_basis="legitimate_interests", detail={"lawful_basis_reason": li})
    store.write("draft-c-001.txt", draft, personal_data_categories=cats, lawful_basis="legitimate_interests")
    # Lawful-basis rule for the send itself (UK GDPR Art 6 plus PECR reg 22).
    if contact["subscriber_type"] == "individual" and not contact["marketing_consent"]:
        lb, why = "unclear", ("PECR reg 22: contact recorded as an individual subscriber with no consent "
                              "or soft opt-in record, so the agent cannot confirm the send is lawful")
    else:
        lb, why = "legitimate_interests", li
    payload = {"to": "contact:c-001", "body_sha256": digest(draft)}
    try:
        tr.call("email_send", "send_email", lambda: (None, None), payload=payload,
                personal_data_categories=cats, lawful_basis=lb, recipients=["contact:c-001 (synthetic)"],
                detail={"lawful_basis_reason": why})
        result = "sent"
    except ApprovalRequired as e:
        store.write("approval-request.json", json.dumps(
            {"action_sha256": e.action_sha256, "tool": "email_send", "to": "contact:c-001",
             "draft": "draft-c-001.txt", "lawful_basis": lb, "reason": why}, indent=2, sort_keys=True) + "\n",
            personal_data_categories=["identifier:customer_ref"], lawful_basis="legitimate_interests")
        result = "draft saved; send blocked pending human approval; nothing sent"
    ctx.record(operation="invoke_agent", action="task_end", outcome="awaiting_approval", detail={"result": result})
    return task


# ---------------------------------------------------------------- run 3
def run3(root: Path, out: Path) -> str:
    """Multi-agent: orchestrator delegates ticket classification to a worker."""
    log = _setup(root, out, "2026-11-10T11:00:00Z")
    task = "Triage six synthetic support tickets; delegate classification to the worker agent"
    o, otr, ostore = _agent(root, out, log, "orchestrator", "run3-orch-s1", task)
    o.record(operation="invoke_agent", action="task_start", outcome="ok", detail={"task": task})
    src = root / "data" / "synthetic" / "tickets.json"
    cats = ["identifier:name", "identifier:customer_ref", "content:customer_message"]
    tickets = otr.call("ticket_read", "read_queue",
                       lambda: (json.loads(src.read_text())["tickets"],
                                {"source": "data/synthetic/tickets.json", "content_sha256": file_digest(src),
                                 "synthetic": True}),
                       payload={"queue": "inbox"}, personal_data_categories=cats, lawful_basis="contract")
    ostore.write("tickets.json", json.dumps(tickets, indent=2) + "\n", personal_data_categories=cats,
                 lawful_basis="contract")

    wtask = "Classify the handed-off tickets; return labels only"
    w, wtr, wstore = _agent(root, out, log, "worker", "run3-worker-s1", wtask,
                            delegated_by="acp.orchestrator", delegated_authority=["classify", "session_store"])
    o.record(operation="invoke_agent", action="delegate", outcome="ok", recipients=["agent:acp.worker"],
             detail={"to_session": w.session_id, "worker_manifest_sha256": w.digest,
                     "delegated_authority": ["classify", "session_store"]})
    ostore.handoff("tickets.json", wstore, personal_data_categories=cats, lawful_basis="contract")

    w.record(operation="invoke_agent", action="task_start", outcome="ok",
             detail={"task": wtask, "delegated_by": "acp.orchestrator"})
    wt = json.loads(wstore.read("tickets.json", personal_data_categories=cats, lawful_basis="contract"))
    try:  # deliberate probe of session isolation
        wstore.read("../run3-orch-s1/tickets.json", detail={"probe": True})
    except IsolationError:
        pass
    rules_p = root / "data" / "classify-rules.json"
    rules = json.loads(rules_p.read_text())
    prop = {"lawful_basis_reason": "propagated: carries the health data found by classify_ticket (T-103)"}
    results = []
    for t in wt:
        def classify(t=t):
            msg = t["message"].lower()
            label = next((k for k, kws in rules["categories"].items() if any(x in msg for x in kws)), "other")
            special = [c for c, kws in rules["special_category_keywords"].items() if any(x in msg for x in kws)]
            ov = {"detail": {"label": label}}
            if special:
                ov.update(personal_data_categories=cats + special, lawful_basis="unclear",
                          detail={"label": label, "lawful_basis_reason":
                                  "special category data (health) found; no Art 9 condition recorded in manifest"})
            return ({"ticket_id": t["ticket_id"], "label": label, "special": special},
                    {"rules_sha256": file_digest(rules_p), "content_sha256": digest(t)}, ov)
        results.append(wtr.call("classify", "classify_ticket", classify, payload={"ticket_id": t["ticket_id"]},
                                personal_data_categories=cats, lawful_basis="contract",
                                detail={"ticket_id": t["ticket_id"]}))
    wstore.write("results.json", json.dumps(results, indent=2) + "\n",
                 personal_data_categories=["identifier:customer_ref", "special_category:health"],
                 lawful_basis="unclear", detail=prop)
    wstore.handoff("results.json", ostore, personal_data_categories=["identifier:customer_ref",
                                                                     "special_category:health"],
                   lawful_basis="unclear", detail=prop)
    w.record(operation="invoke_agent", action="task_end", outcome="ok",
             detail={"result": f"{len(results)} tickets classified"})

    res = json.loads(ostore.read("results.json", personal_data_categories=["identifier:customer_ref",
                                                                           "special_category:health"],
                                 lawful_basis="unclear", detail=prop))
    stub = out / "stub_systems"
    stub.mkdir(exist_ok=True)
    routed, cancelled = [], []
    for r in res:
        if r["special"] or r["label"] == "data_rights_request":
            reason = "lawful_basis_unclear" if r["special"] else "data_rights_request"
            lb = "unclear" if r["special"] else "legal_obligation"
            otr.call("human_queue", "route_to_human",
                     lambda r=r: (None, {"stub": True, "system": "stub_systems/human_queue.jsonl"}),
                     payload={"ticket_id": r["ticket_id"]}, personal_data_categories=["identifier:customer_ref"],
                     lawful_basis=lb, detail={"ticket_id": r["ticket_id"], "reason": reason,
                                                     **(prop if r["special"] else {})})
            with open(stub / "human_queue.jsonl", "a") as f:
                f.write(json.dumps({"ticket_id": r["ticket_id"], "reason": reason}, sort_keys=True) + "\n")
            routed.append(r["ticket_id"])
        elif r["label"] == "cancellation":
            payload = {"ticket_id": r["ticket_id"], "customer_ref": "cust-0002"}

            def cancel(p=payload):
                with open(stub / "subscriptions.jsonl", "a") as f:
                    f.write(json.dumps({"cancelled": p["customer_ref"]}, sort_keys=True) + "\n")
                return None, {"stub": True, "system": "stub_systems/subscriptions.jsonl"}
            kw = dict(payload=payload, personal_data_categories=["identifier:customer_ref"],
                      lawful_basis="contract", detail={"ticket_id": r["ticket_id"]})
            try:
                otr.call("subscription_cancel", "cancel_subscription", cancel, **kw)
            except ApprovalRequired as e:
                # Simulated human reviewer (clearly marked) approves this exact action.
                write_approval(out / "approvals", e.action_sha256, approver="reviewer-1 (synthetic)",
                               note="customer asked to cancel; checked ticket text", simulated=True,
                               at=log.clock.now())
                otr.call("subscription_cancel", "cancel_subscription", cancel, **kw)
            cancelled.append(r["ticket_id"])
    o.record(operation="invoke_agent", action="task_end", outcome="ok",
             detail={"result": f"{len(res)} tickets triaged; routed to human: {', '.join(routed)}; "
                               f"cancelled after approval: {', '.join(cancelled)}; others left for standard handling"})
    return task


RUNS = {"1": run1, "2": run2, "3": run3}
