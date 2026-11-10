# Intro email to c-001: blocked, nothing sent

## What happened
- Read CRM contact c-001 and rendered the intro template.
- Requested email_send. The control gate refused it with `blocked_pending_approval`: a human must approve this exact message first, and no approval exists. Nothing was sent.

## Before approving, a reviewer should note
- The body I submitted differs slightly from the rendered template. I changed "writing to you as Operations Manager" to "writing to you in your role as Operations Manager". Approval must cover the exact text that will be sent.
- **PECR risk:** c-001 is recorded as subscriber_type = `individual` with marketing_consent = `null`. Unsolicited electronic marketing to individual subscribers generally needs consent or a valid soft opt-in, and neither is recorded. Legitimate interests (UK GDPR Art 6(1)(f)) alone may not satisfy PECR.
- **Action needed:** confirm whether the contact is actually a corporate subscriber (for example, a work email address) or obtain consent before approving.

## Status
No retry was attempted. Waiting for a human decision.