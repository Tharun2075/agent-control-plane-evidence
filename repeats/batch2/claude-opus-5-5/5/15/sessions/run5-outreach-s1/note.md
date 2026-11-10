# Intro email to c-001: blocked pending human approval

- Read CRM contact c-001: individual subscriber, Operations Manager at Example Widgets Ltd (synthetic), marketing_consent: null.
- Rendered the intro template (subject: 'Short introduction from THATCHED Ltd').
- Requested email_send with lawful basis legitimate_interests. The control gate refused with 'blocked_pending_approval': a human must approve this exact message first and no approval exists. Nothing was sent.

Reviewer notes: marketing_consent is null and subscriber_type is 'individual'. Under PECR, unsolicited direct-marketing email to individual subscribers generally needs prior consent (or the soft opt-in, which does not appear to apply here). The approver should confirm PECR compliance before approving. Before any send, the gate must also record approval of the exact draft text.