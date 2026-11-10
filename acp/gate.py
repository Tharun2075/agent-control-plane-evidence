"""B1d: tool runner with permission check and approval gate.

Every tool call goes through ToolRunner.call(). It
1. refuses a tool the manifest does not allow (logged, outcome refused_not_permitted);
   It also refuses (logged) once current_task.expires has passed, and treats a
   missing delegated_authority as no authority (fail closed). This is authorise(),
   the one check SessionStore (write, read, handoff) also calls;
2. for a tool the manifest marks outbound or irreversible, computes
   action_sha256 over (agent, session, tool, action, payload) and looks for an
   approval record approvals/<first 16 hex>.json whose action_sha256 matches.
   No record: the call is blocked and logged (outcome blocked_pending_approval).
   A changed payload changes the digest, so an approval cannot be reused for a
   different message or recipient;
   An approval is single-use: before the tool runs, the call claims it by
   creating approvals/<name>.claimed with O_CREAT|O_EXCL, an atomic step even
   across processes. Only the call that creates the marker runs the tool; a
   second caller is refused and logged. The record is then marked consumed with
   the log record and outcome (ok or error) of the call that used it, so a tool
   that raises does not leave a reusable approval;
3. checks URLs by parsed, normalised parts, not by raw string (see check_url);
   a tool that reports a final URL after redirects has that URL checked too;
4. runs the tool and logs the result with its provenance and decision mode.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import unquote, urlsplit, urlunsplit

from .agent import AgentContext
from .canon import canonical, digest
from .manifest import tool_spec


def _parse(ts: str) -> datetime:
    if not isinstance(ts, str):  # e.g. an int: invalid, so callers fail closed and log it
        raise ValueError(f"expires must be an ISO 8601 string, not {type(ts).__name__}")
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


class PermissionDenied(Exception):
    def __init__(self, message: str, outcome: str = "refused_not_permitted"):
        super().__init__(message)
        self.outcome = outcome


class ApprovalRequired(Exception):
    def __init__(self, action_sha256: str):
        super().__init__(f"approval required for action {action_sha256}")
        self.action_sha256 = action_sha256


class Rejected(Exception):
    pass


def authorise(ctx: AgentContext, tool: str, base: dict, detail: dict) -> None:
    """The one authority check for every agent action (ToolRunner.call and
    SessionStore write/read/handoff). Refuses, with a log record built from
    base + detail, once current_task.expires has passed (or is missing or
    invalid), and any tool not in both allowed_tools and delegated_authority.
    A missing delegated_authority counts as no authority (fail closed)."""
    allowed = ctx.manifest["permissions"].get("allowed_tools", [])
    authority = ctx.manifest["current_task"].get("delegated_authority")
    if authority is None:  # fail closed: no stated authority means none
        authority = []
    expires = ctx.manifest["current_task"].get("expires")
    now = ctx.log.clock.current()
    try:
        expired = not expires or now >= _parse(expires)
    except ValueError:
        ctx.record(**base, outcome="refused_authority_expired",
                   detail={**detail, "gate": "refused", "expires": expires, "reason": "invalid expires"})
        raise
    if expired:
        ctx.record(**base, outcome="refused_authority_expired",
                   detail={**detail, "gate": "refused", "expires": expires})
        raise PermissionDenied(f"{ctx.agent_id} authority expired or has no expiry ({expires})",
                               "refused_authority_expired")
    if tool not in allowed or tool not in authority:
        ctx.record(**base, outcome="refused_not_permitted", detail={**detail, "gate": "refused"})
        raise PermissionDenied(f"{ctx.agent_id} may not use {tool}")


def recipient_expired(recipient: AgentContext, now) -> bool:
    """True when the recipient's current_task.expires has passed, is missing
    or is invalid (fail closed). Used by SessionStore.handoff so a valid
    session cannot push data into an expired session's store."""
    expires = recipient.manifest["current_task"].get("expires")
    try:
        return not expires or now >= _parse(expires)
    except ValueError:
        return True


def action_digest(ctx: AgentContext, tool: str, action: str, payload) -> str:
    return digest(
        {"agent": ctx.agent_id, "session": ctx.session_id, "tool": tool, "action": action, "payload": payload}
    )


def approval_path(approvals_dir: Path, action_sha256: str) -> Path:
    return Path(approvals_dir) / (action_sha256.split(":", 1)[1][:16] + ".json")


def write_approval(
    approvals_dir: Path,
    action_sha256: str,
    *,
    approver: str,
    decision: str = "approve",
    note: str = "",
    simulated: bool = False,
    at: str = "",
) -> Path:
    if decision not in ("approve", "reject"):
        raise ValueError("decision must be approve or reject")
    p = approval_path(approvals_dir, action_sha256)
    p.parent.mkdir(parents=True, exist_ok=True)
    rec = {
        "action_sha256": action_sha256,
        "approver": approver,
        "decision": decision,
        "note": note,
        "simulated": simulated,
        "at": at,
    }
    p.write_bytes(canonical(rec) + b"\n")
    return p


DEFAULT_PORTS = {"http": 80, "https": 443}


class UrlRefused(ValueError):
    pass


def _segments(path: str, fold: bool = False) -> list[str]:
    """Path -> whole segments, empty segments dropped; lower-cased when fold."""
    return [x.lower() if fold else x for x in path.split("/") if x]


def normalise_url(url: str) -> tuple[str, str, int, str, str]:
    """(scheme, host, port, decoded path, decoded query). Raises UrlRefused for
    anything the gate and the fetcher could read differently, so the gate never
    judges a rewritten URL while the tool fetches the raw one: non-http(s)
    scheme, userinfo, no host, bad port, backslash or control characters,
    encoded '/', '\\' or '.', ';' path parameters, '.' or '..' segments, or a
    path still percent-encoded after one decode (double encoding)."""
    if "\\" in url or any(ord(c) < 0x20 for c in url):
        raise UrlRefused("backslash or control character in URL")
    try:
        u = urlsplit(url)
        port = u.port
    except ValueError as e:
        raise UrlRefused(f"unparseable URL ({e})")
    scheme = u.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise UrlRefused(f"scheme {scheme or '(none)'} is not http or https")
    if "@" in u.netloc:
        raise UrlRefused("userinfo in URL")
    host = (u.hostname or "").rstrip(".")
    if not host:
        raise UrlRefused("no host")
    raw = u.path.lower()
    if any(e in raw for e in ("%2f", "%5c", "%2e")) or ";" in raw:
        raise UrlRefused("encoded separator or ';' parameter in path")
    path = unquote(u.path)
    if "%" in path or "\\" in path or any(ord(c) < 0x20 for c in path):
        raise UrlRefused("encoded or unsafe characters left in path after one decode")
    if any(x in (".", "..") for x in path.split("/")):
        raise UrlRefused("dot segment in path")
    return scheme, host, port or DEFAULT_PORTS[scheme], path, unquote(u.query)


def normalised_url_string(url: str) -> str:
    """normalise_url() as one URL string (default port dropped, path and query
    decoded), for the log: it shows the target the gate judged."""
    scheme, host, port, path, query = normalise_url(url)
    netloc = host if port == DEFAULT_PORTS[scheme] else f"{host}:{port}"
    return urlunsplit((scheme, netloc, path, query, ""))


def _has_run(segs: list[str], run: list[str]) -> bool:
    n = len(run)
    return n > 0 and any(segs[i:i + n] == run for i in range(len(segs) - n + 1))


def check_url(url: str, allowed_prefixes, blocked_patterns) -> tuple[str, list | str] | None:
    """None if the URL may be used, else (reason, matched). Blocked patterns
    match whole path segments anywhere in the path; an allowed prefix must have
    the same scheme, host and port and its path segments (case-sensitive)
    must lead the URL's."""
    if not url:
        return None
    try:
        scheme, host, port, path, query = normalise_url(url)
    except UrlRefused as e:
        return str(e), "unsafe URL"
    # Blocked: whole segments, case-folded, anywhere in the path; plus the old
    # substring rule on the decoded, case-folded path and query, so the list
    # never blocks less than it did.
    low = (path + "?" + query).lower()
    blocked = [b for b in blocked_patterns or []
               if _has_run(_segments(path, True), _segments(unquote(b), True)) or unquote(b).lower() in low]
    if blocked:
        return "blocked pattern", blocked
    if allowed_prefixes is not None:
        segs = _segments(path)
        for x in allowed_prefixes:
            try:
                xs, xh, xp, xpath, _ = normalise_url(x)
            except UrlRefused:
                continue
            xsegs = _segments(xpath)
            if (xs, xh, xp) == (scheme, host, port) and segs[:len(xsegs)] == xsegs:
                return None
        return "outside allowed_url_prefixes", "not in allowed_url_prefixes"
    return None


class ToolRunner:
    def __init__(self, ctx: AgentContext, approvals_dir: Path):
        self.ctx = ctx
        self.approvals_dir = Path(approvals_dir)

    def requires_approval(self, tool: str) -> bool:
        spec = tool_spec(self.ctx.manifest, tool) or {}
        triggers = set(self.ctx.manifest["permissions"].get("approval_required_for", []))
        return bool(
            ("outbound" in triggers and spec.get("outbound"))
            or ("irreversible" in triggers and spec.get("irreversible"))
            or tool in triggers
        )

    def call(
        self,
        tool: str,
        action: str,
        fn: Callable[[], tuple],
        *,
        payload=None,
        personal_data_categories=None,
        lawful_basis: str = "not_applicable",
        recipients=(),
        detail: dict | None = None,
    ):
        """fn() returns (value, provenance_or_None[, overrides]). overrides may set
        personal_data_categories, lawful_basis and detail from what the tool found."""
        ctx = self.ctx
        base = dict(
            operation="execute_tool",
            tool=tool,
            action=action,
            personal_data_categories=personal_data_categories,
            lawful_basis=lawful_basis,
            recipients=recipients,
        )
        detail = dict(detail or {})
        authorise(ctx, tool, base, detail)
        now = ctx.log.clock.current()

        url = payload.get("url", "") if isinstance(payload, dict) else ""
        perms = ctx.manifest["permissions"]
        prefixes, patterns = perms.get("allowed_url_prefixes"), perms.get("blocked_url_patterns", [])
        bad = check_url(url, prefixes, patterns)
        if bad:
            ctx.record(**base, outcome="refused_purpose_limitation",
                       detail={**detail, "gate": "refused", "url": url, "matched": bad[1]})
            raise PermissionDenied(f"{url} refused: {bad[0]} {bad[1]}")
        if url:  # log the decoded target next to the raw URL, only when they differ
            norm = normalised_url_string(url)
            if norm != url:
                detail["normalised_url"] = norm

        decision_mode, approval_ref = "automated", None
        if self.requires_approval(tool):
            a = action_digest(ctx, tool, action, payload)
            p = approval_path(self.approvals_dir, a)
            appr = json.loads(p.read_bytes()) if p.exists() else None
            claim = p.with_name(p.name + ".claimed")
            reason = None
            if not appr or appr.get("action_sha256") != a:
                reason = "no approval record"
            elif appr.get("consumed") or claim.exists():
                reason = "approval already used"
            elif appr["decision"] == "approve":
                try:  # atomic claim: exactly one caller creates the marker
                    fd = os.open(claim, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
                except FileExistsError:
                    reason = "approval already used"
                else:
                    with os.fdopen(fd, "wb") as f:
                        f.write(canonical({"action_sha256": a, "claimed_at": now.isoformat()}) + b"\n")
            if reason:
                ctx.record(
                    **base,
                    outcome="blocked_pending_approval",
                    detail={**detail, "gate": "blocked", "action_sha256": a, "reason": reason},
                )
                raise ApprovalRequired(a)
            approval_ref = p.name
            detail.update(gate="approved" if appr["decision"] == "approve" else "rejected",
                          action_sha256=a, approver=appr["approver"], approval_simulated=appr["simulated"])
            if appr["decision"] != "approve":
                ctx.record(**base, outcome="rejected_by_human", decision_mode="human_rejected",
                           approval_ref=approval_ref, detail=detail)
                raise Rejected(a)
            decision_mode = "human_approved"
        def consume(rec):  # one approval, one action, whatever the outcome
            appr["consumed"] = True
            appr["consumed_by"] = {"log_seq": rec["seq"], "log_hash": rec["hash"], "outcome": rec["outcome"]}
            tmp = p.with_name(p.name + ".tmp")
            tmp.write_bytes(canonical(appr) + b"\n")
            os.replace(tmp, p)

        try:
            out = fn()
            value, provenance = out[0], out[1]
            if len(out) > 2:  # tool reports what it actually found (e.g. special category data)
                ov = out[2]
                base["personal_data_categories"] = ov.get("personal_data_categories", base["personal_data_categories"])
                base["lawful_basis"] = ov.get("lawful_basis", base["lawful_basis"])
                detail.update(ov.get("detail", {}))
        except Exception as e:  # logged, then re-raised
            rec = ctx.record(**base, outcome="error", decision_mode=decision_mode, approval_ref=approval_ref,
                             detail={**detail, "error": type(e).__name__})
            if approval_ref:
                consume(rec)
            raise
        final_url = detail.get("final_url")
        bad = check_url(final_url, prefixes, patterns) if final_url and final_url != url else None
        if bad:  # the tool followed a redirect out of purpose: discard the result
            rec = ctx.record(**base, outcome="refused_purpose_limitation", decision_mode=decision_mode,
                             approval_ref=approval_ref,
                             detail={**detail, "gate": "refused", "url": url, "matched": bad[1]})
            if approval_ref:
                consume(rec)
            raise PermissionDenied(f"final URL {final_url} refused: {bad[0]} {bad[1]}")
        rec = ctx.record(**base, outcome="ok", decision_mode=decision_mode, approval_ref=approval_ref,
                         provenance=provenance, detail=detail)
        if approval_ref:
            consume(rec)
        return value
