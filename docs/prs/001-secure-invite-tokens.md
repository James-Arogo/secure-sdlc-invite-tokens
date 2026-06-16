# PR 001: Secure Invite Tokens

## Summary

Add invitation-token creation and verification for onboarding workflows. Tokens carry a subject, audience, issued-at timestamp, and expiry timestamp.

## Threat Model

### Assets

- invite authorization state
- tenant or audience boundary
- onboarding workflow integrity

### Actors

- legitimate invite recipient
- external attacker with a copied token
- insider or service caller trying to reuse a token in the wrong audience

### Abuse Cases

- tamper with the subject to impersonate another user
- extend token expiry
- replay a copied token against a different audience
- submit malformed payloads to trigger parser failures

### Controls

- enforce explicit audience during verification
- enforce token expiry
- reject malformed or incomplete claims
- add tests for security-relevant validation

## Validation

Run:

```bash
python3 -m unittest discover -s tests
```

