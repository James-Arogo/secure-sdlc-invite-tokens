# Submission Write-Up: Secure SDLC Invite Tokens

## 1. Feature Built and Threat Model

I built a small Python feature called `secure_invites` that creates and verifies invite tokens for an onboarding flow. The reason this feature matters from a security perspective is that invite tokens act like temporary authorization: whoever presents a valid token can enter a protected workflow for a specific audience, such as `partner-portal`.

The main threats I considered were token tampering, replay, expiry bypass, and audience confusion. An attacker who obtains a token should not be able to change the subject from `user-123` to an admin user, extend the expiry time, or reuse the same token against a different audience such as `admin-console`. The final implementation protects the token payload with HMAC-SHA256, validates expiry, validates the expected audience, rejects malformed claims, and uses `hmac.compare_digest` for constant-time signature comparison.

## 2. Vulnerability Found and Remediated

The initial implementation in commit `86751e3` added invite tokens as base64url-encoded JSON. That was intentionally vulnerable because base64 is only encoding, not integrity protection. The root cause was that the verifier trusted decoded JSON claims without proving that the claims were issued by the server. An attacker could decode the payload, change fields like `sub` or `exp`, re-encode it, and submit the tampered token.

The review finding is documented in commit `1619f8b` and in `docs/reviews/001-security-review.md`. The remediation is commit `42ec7fc`, which changed the token format to `payload.signature`, where the signature is HMAC-SHA256 over canonical JSON. Verification now recomputes the expected signature and rejects the token if `hmac.compare_digest` fails. This fixed the claim-tampering vulnerability while keeping the existing expiry and audience checks.

## 3. Code Review Evidence

Code review is represented by `docs/reviews/001-security-review.md` and commit `1619f8b`. The review explicitly blocked shipping because the baseline token format was unsigned and therefore tamperable. The required changes from review were to sign the canonical payload, verify signatures with constant-time comparison, add a tampering regression test, and keep the expiry/audience tests.

The follow-up remediation commit `42ec7fc` addresses those review comments directly. It adds the HMAC signature, requires a secret for token creation and verification, rejects invalid signatures, and updates the PR/threat-model note in `docs/prs/001-secure-invite-tokens.md` to reflect the final controls.

## 4. Security Tests Written

The security-relevant tests are in `tests/test_invites.py`. They assert that a valid token round-trips into trusted claims, expired tokens are rejected, tokens for the wrong audience are rejected, tampered payloads are rejected, and tokens verified with the wrong secret are rejected.

The most important regression test is `test_rejects_tampered_payload`. It creates a legitimate token, modifies the encoded payload to change the subject, keeps the original signature, and verifies that the implementation rejects it with a signature error. This proves the original vulnerability is fixed. The test suite can be run with:

```bash
python3 -m unittest discover -s tests
```

At submission time, the suite passed with 5 tests.

## 5. AI Usage

I used AI to scaffold the small Python feature, draft the threat model and review notes, generate security-focused unit tests, and identify/remediate the unsigned-token vulnerability. I also used AI to structure the git history so the repo shows the baseline implementation, the review finding, and the remediation as separate commits.
