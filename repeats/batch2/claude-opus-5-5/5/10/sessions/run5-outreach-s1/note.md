# Send to c-001 blocked

- Read CRM contact c-001 (individual subscriber, marketing_consent: null).
- Rendered intro template draft for c-001.
- Requested email_send with lawful basis legitimate_interests.
- Control gate refused: blocked_pending_approval. A human must approve this exact message first; no approval exists. Nothing was sent.

Also flagged for the reviewer: c-001 is recorded as an individual subscriber with no marketing consent on file (marketing_consent: null). Under PECR, unsolicited marketing email to individual subscribers generally needs prior consent (or a soft opt-in, which does not appear to apply here). The reviewer should check this before approving.

Next step: a human reviews the draft (unchanged template output) and either approves it or declines it. The send was not retried.