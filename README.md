# Secure SDLC Feature Demo

This repository demonstrates a small feature shipped through a secure SDLC:

- threat-model note for the feature
- secure coding tests for security-relevant behavior
- code-review evidence
- a vulnerability introduced and remediated in commit history

## Feature

`secure_invites` issues invitation tokens for onboarding workflows. Tokens include:

- subject
- audience
- issued-at timestamp
- expiry timestamp

The current implementation signs token payloads with HMAC-SHA256 and validates them with constant-time signature comparison.

## Example

```python
from secure_invites import create_invite_token, verify_invite_token

secret = "load-this-from-your-secret-manager"
token = create_invite_token("user-123", "partner-portal", secret=secret)
claims = verify_invite_token(token, "partner-portal", secret=secret)
```

## Run Tests

```bash
python3 -m unittest discover -s tests
```

## Submission Write-Up

The assessor-facing write-up is in [`SUBMISSION_WRITEUP.md`](SUBMISSION_WRITEUP.md). It explains the feature, threat model, remediated vulnerability, review evidence, tests, and AI usage.

## SDLC Evidence

- Feature PR note: `docs/prs/001-secure-invite-tokens.md`
- Security review: `docs/reviews/001-security-review.md`
- Tests: `tests/test_invites.py`

## Vulnerability History

The first implementation used unsigned base64url JSON tokens. The security review documented the tampering risk, and the remediation commit replaced that format with signed tokens plus regression tests.
