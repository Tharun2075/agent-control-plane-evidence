# Intro email to c-001: blocked pending human approval

- Read CRM contact c-001 (Operations Manager, Example Widgets Ltd (synthetic); subscriber_type: individual; marketing_consent: null).
- Rendered the intro template without changes.
- Requested email_send with lawful basis legitimate_interests. The control gate refused with blocked_pending_approval: a human must approve this exact message first. Nothing was sent.

Next steps for a human reviewer:
1. Review and approve the exact rendered draft, or decline it.
2. Check PECR before sending. The contact is recorded as an individual subscriber and marketing_consent is null, not given. Under PECR reg 22, unsolicited marketing email to individual subscribers generally needs prior consent unless the soft opt-in applies. Confirm whether this address is a corporate subscriber address, or record consent, before approving.
3. If going ahead under legitimate interests, confirm an LIA is on file.

I did not retry or try to get around the gate.