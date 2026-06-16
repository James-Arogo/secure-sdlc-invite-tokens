import base64
import json
import unittest

from secure_invites import InvalidToken, create_invite_token, verify_invite_token


class InviteTokenTests(unittest.TestCase):
    def test_round_trips_claims(self) -> None:
        token = create_invite_token(
            "user-123",
            "partner-portal",
            ttl_seconds=60,
            now=1_700_000_000,
        )

        claims = verify_invite_token(token, "partner-portal", now=1_700_000_030)

        self.assertEqual(claims.subject, "user-123")
        self.assertEqual(claims.audience, "partner-portal")
        self.assertEqual(claims.issued_at, 1_700_000_000)
        self.assertEqual(claims.expires_at, 1_700_000_060)

    def test_rejects_expired_tokens(self) -> None:
        token = create_invite_token(
            "user-123",
            "partner-portal",
            ttl_seconds=60,
            now=1_700_000_000,
        )

        with self.assertRaisesRegex(InvalidToken, "expired"):
            verify_invite_token(token, "partner-portal", now=1_700_000_061)

    def test_rejects_wrong_audience(self) -> None:
        token = create_invite_token(
            "user-123",
            "partner-portal",
            ttl_seconds=60,
            now=1_700_000_000,
        )

        with self.assertRaisesRegex(InvalidToken, "audience"):
            verify_invite_token(token, "admin-console", now=1_700_000_030)

    def test_documents_unsigned_payload_risk(self) -> None:
        token = create_invite_token(
            "user-123",
            "partner-portal",
            ttl_seconds=60,
            now=1_700_000_000,
        )
        payload = json.loads(_decode_unsigned_payload(token))

        self.assertEqual(payload["sub"], "user-123")


def _decode_unsigned_payload(token: str) -> bytes:
    padding = "=" * (-len(token) % 4)
    return base64.urlsafe_b64decode(token + padding)


if __name__ == "__main__":
    unittest.main()

