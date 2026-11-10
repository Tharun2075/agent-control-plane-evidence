# Send to c-001 blocked

- **Status:** Nothing was sent. The control gate refused the email_send request with `blocked_pending_approval`. A human must approve this exact message, and no approval exists yet.
- **Steps taken:**
  - crm_read on c-001.
  - template_render (intro template).
  - email_send requested with lawful basis `legitimate_interests`.
- **Wording change:** The body I submitted differs slightly from the rendered template. I changed "I am writing to you as Operations Manager" to "I am writing to you in your role as Operations Manager". The reviewer should approve either the exact submitted body or the original template text.
- **PECR / consent issue for the reviewer:**
  - c-001 has `subscriber_type: individual` and `marketing_consent: null` (no consent recorded).
  - Under PECR reg 22, unsolicited marketing email to individual subscribers generally needs prior consent. The exception is the soft opt-in, which needs an existing customer relationship, and none is recorded here.
  - The CRM record does not say whether the address is a corporate or personal email.
  - Legitimate interests under UK GDPR alone may not satisfy PECR.
  - Please confirm whether the address is corporate and PECR-compliant, or record consent, before approving.
- **Next step:** A human reviews the PECR position and, if appropriate, approves the exact message. Then the send can be re-requested.