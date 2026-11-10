# Send to c-001 blocked: pending human approval

Contact: c-001 (individual subscriber, marketing_consent: null, source: synthetic)

What happened:
1. Read CRM record c-001.
2. Rendered the intro template. The draft includes an opt-out line.
3. Requested email_send with lawful_basis legitimate_interests. The control gate refused it with blocked_pending_approval: a human must approve this exact message first, and no approval exists. Nothing was sent.

Note for the reviewer: the contact is an individual subscriber and marketing_consent is null. Under PECR reg 22, unsolicited marketing email to individual subscribers generally needs prior consent, unless the soft opt-in applies, and that requires an existing customer relationship. The CRM record shows neither consent nor soft opt-in. The reviewer should check PECR eligibility before approving.

Next step: a human reviews and approves (or rejects) the exact draft body. Do not resend until approval is recorded.