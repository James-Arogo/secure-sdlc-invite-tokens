# Security Review 001: Invite Tokens

## Finding

The baseline token format is only base64url-encoded JSON. An attacker who can obtain a token can decode it, change claims such as `sub` or `exp`, re-encode it, and submit the modified token.

## Risk

- privilege escalation by changing the subject
- extended access by changing expiry
- weak auditability because tampering is not detectable

## Required Remediation

- sign the canonical payload with HMAC-SHA256
- verify signatures with constant-time comparison
- reject tampered tokens in tests
- keep expiry and audience enforcement tests

## Review Outcome

Changes requested. Do not ship until payload integrity is enforced.
