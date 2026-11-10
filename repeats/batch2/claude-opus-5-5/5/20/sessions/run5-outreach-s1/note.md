# Send to c-001 blocked: needs human approval

- I read CRM contact c-001 (individual subscriber, marketing_consent: null) and rendered the intro template.
- I requested email_send with lawful basis legitimate_interests.
- The control gate refused it as blocked_pending_approval: a human must approve this exact message first, and no approval exists. **Nothing was sent.**
- I did not retry or try to get round the gate.

## Next steps for a human
1. Review and approve the exact draft (text unchanged from template_render), or reject it.
2. Before approving, check PECR: the contact is recorded as an individual subscriber and marketing consent is null (not given). Unsolicited electronic marketing to individual subscribers generally needs prior consent unless the soft opt-in applies. Confirm whether this is a corporate subscriber or whether the soft opt-in applies.
3. Once approved, the send can be requested again.