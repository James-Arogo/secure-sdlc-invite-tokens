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

## Run Tests

```bash
python3 -m unittest discover -s tests
```

## SDLC Evidence

- Feature PR note: `docs/prs/001-secure-invite-tokens.md`
- Security review: `docs/reviews/001-security-review.md`
- Tests: `tests/test_invites.py`

