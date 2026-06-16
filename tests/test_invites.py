import base64
import json
import unittest

from secure_invites import InvalidToken, create_invite_token, verify_invite_token


SECRET = "test-secret-with-enough-entropy"


class InviteTokenTests(unittest.TestCase):
    def test_round_trips_claims(self) -> None:
        token = create_invite_token(
            "user-123",
            "partner-portal",
            secret=SECRET,
            ttl_seconds=60,
            now=1_700_000_000,
        )

        claims = verify_invite_token(
            token,
            "partner-portal",
            secret=SECRET,
            now=1_700_000_030,
        )

        self.assertEqual(claims.subject, "user-123")
        self.assertEqual(claims.audience, "partner-portal")
        self.assertEqual(claims.issued_at, 1_700_000_000)
        self.assertEqual(claims.expires_at, 1_700_000_060)

    def test_rejects_expired_tokens(self) -> None:
        token = create_invite_token(
            "user-123",
            "partner-portal",
            secret=SECRET,
            ttl_seconds=60,
            now=1_700_000_000,
        )

        with self.assertRaisesRegex(InvalidToken, "expired"):
            verify_invite_token(
                token,
                "partner-portal",
                secret=SECRET,
                now=1_700_000_061,
            )

    def test_rejects_wrong_audience(self) -> None:
        token = create_invite_token(
            "user-123",
            "partner-portal",
            secret=SECRET,
            ttl_seconds=60,
            now=1_700_000_000,
        )

        with self.assertRaisesRegex(InvalidToken, "audience"):
            verify_invite_token(
                token,
                "admin-console",
                secret=SECRET,
                now=1_700_000_030,
            )

    def test_rejects_tampered_payload(self) -> None:
        token = create_invite_token(
            "user-123",
            "partner-portal",
            secret=SECRET,
            ttl_seconds=60,
            now=1_700_000_000,
        )
        encoded_payload, signature = token.split(".", 1)
        payload = json.loads(_b64url_decode(encoded_payload))
        payload["sub"] = "admin-999"
        tampered_payload = _b64url_encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )

        with self.assertRaisesRegex(InvalidToken, "signature"):
            verify_invite_token(
                f"{tampered_payload}.{signature}",
                "partner-portal",
                secret=SECRET,
                now=1_700_000_030,
            )

    def test_rejects_wrong_secret(self) -> None:
        token = create_invite_token(
            "user-123",
            "partner-portal",
            secret=SECRET,
            ttl_seconds=60,
            now=1_700_000_000,
        )

        with self.assertRaisesRegex(InvalidToken, "signature"):
            verify_invite_token(
                token,
                "partner-portal",
                secret="different-secret",
                now=1_700_000_030,
            )


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


if __name__ == "__main__":
    unittest.main()
