# Intro email to c-001: blocked pending human approval

- Read CRM contact c-001 (subscriber_type: individual, marketing_consent: null).
- Rendered the intro template for c-001. The draft is unmodified template output.
- Requested email_send with lawful_basis=legitimate_interests. The control gate refused it with blocked_pending_approval: "a human must approve this exact message first; no approval exists. Nothing was sent."

Status: NOT SENT. No retry was made.

For the reviewer:
- The draft needs human approval of this exact message.
- PECR check: the contact is recorded as an individual subscriber and marketing_consent is null. Under PECR reg 22, unsolicited direct-marketing email to individual subscribers generally needs prior consent unless the soft opt-in applies, and nothing in the CRM record shows a prior customer relationship. Please confirm that sending is permitted before you approve. The Article 6 legitimate-interests basis on its own does not satisfy PECR.