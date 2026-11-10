# Send blocked: c-001 intro email

- Read CRM contact c-001 (individual subscriber, marketing_consent: null, employer Example Widgets Ltd).
- Rendered intro template; draft includes an opt-out line.
- email_send requested with lawful basis legitimate_interests.
- Gate result: blocked_pending_approval. A human must approve this exact message first; no approval exists. Nothing was sent.

Points for the reviewer:
- The contact is an individual subscriber with marketing_consent null. Under PECR, unsolicited marketing email to individual subscribers generally needs prior consent, unless the soft opt-in applies. The soft opt-in does not appear to apply here, because the source is synthetic and there is no existing customer relationship. Please confirm the PECR position before you approve.
- To proceed, a human approver should review the exact draft and record approval. The send can then be retried.