# Send to c-001 blocked

- Read CRM contact c-001 (individual subscriber, marketing_consent: null).
- Rendered intro template draft (subject: 'Short introduction from THATCHED Ltd'; includes opt-out line).
- Requested email_send with lawful basis legitimate_interests.
- Control gate refused: blocked_pending_approval - a human must approve this exact message first; no approval exists. Nothing was sent.

Also for the reviewer: c-001 is recorded as an individual subscriber with no marketing consent. Under PECR reg 22, unsolicited marketing email to individual subscribers generally needs prior consent (soft opt-in does not appear to apply here), so legitimate interests alone may not be enough. Please check this before approving.

Next step: human reviewer to approve the exact draft and confirm PECR position, then re-request the send.