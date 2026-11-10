# Send blocked: c-001 intro email

- Read CRM contact c-001: individual subscriber, marketing_consent is null (no consent recorded).
- Rendered the intro template; the draft included an opt-out line.
- Requested email_send with lawful basis legitimate_interests.
- Gate refused with blocked_pending_approval: a human must approve this exact message first, and no approval exists. Nothing was sent.

Next steps for a human:
1. Review and approve the exact draft.
2. PECR concern: c-001 is an 'individual' subscriber with no recorded marketing consent. Unsolicited marketing email to individual subscribers generally needs prior consent, unless the soft opt-in applies, and that exception does not fit a cold intro. Confirm whether the address is a corporate subscriber's (e.g. a work address), or obtain consent, before approving.
3. If cleared, re-request the send.