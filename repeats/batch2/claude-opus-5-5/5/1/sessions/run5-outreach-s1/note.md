# Send to c-001 blocked

- Read CRM contact c-001 and rendered the intro template. The draft is unchanged from the template.
- Requested email_send. The gate refused it with `blocked_pending_approval`: a human must approve this exact message first, and no approval exists. Nothing was sent.
- I did not retry or work around the gate.

## Issue for the human reviewer: PECR

- c-001 is recorded as `subscriber_type: individual` with `marketing_consent: null`.
- Under PECR reg 22, unsolicited marketing email to an individual subscriber generally needs prior consent.
- The soft opt-in does not appear to apply, because there is no record of a previous sale or negotiation.
- Legitimate interests under UK GDPR does not override PECR.
- Before approving, please confirm that the contact counts as a corporate subscriber, or that valid consent exists.

## Next steps

1. Resolve the consent and subscriber-type question.
2. Give human approval of the exact draft.
3. Request the send again.