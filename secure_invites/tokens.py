from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any


class InvalidToken(ValueError):
    """Raised when an invite token cannot be trusted."""


@dataclass(frozen=True)
class TokenClaims:
    subject: str
    audience: str
    issued_at: int
    expires_at: int


def create_invite_token(
    subject: str,
    audience: str,
    *,
    secret: str | bytes,
    ttl_seconds: int = 900,
    now: int | None = None,
) -> str:
    if not subject:
        raise ValueError("subject is required")
    if not audience:
        raise ValueError("audience is required")
    if not secret:
        raise ValueError("secret is required")
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")

    issued_at = int(time.time() if now is None else now)
    claims = {
        "sub": subject,
        "aud": audience,
        "iat": issued_at,
        "exp": issued_at + ttl_seconds,
    }
    payload = _canonical_json(claims)
    signature = _sign(payload, secret)
    return f"{_b64url_encode(payload)}.{_b64url_encode(signature)}"


def verify_invite_token(
    token: str,
    audience: str,
    *,
    secret: str | bytes,
    now: int | None = None,
) -> TokenClaims:
    if not secret:
        raise ValueError("secret is required")

    try:
        encoded_payload, encoded_signature = token.split(".", 1)
        payload = _b64url_decode(encoded_payload)
        supplied_signature = _b64url_decode(encoded_signature)
    except ValueError as exc:
        raise InvalidToken("token format is invalid") from exc

    expected_signature = _sign(payload, secret)
    if not hmac.compare_digest(supplied_signature, expected_signature):
        raise InvalidToken("token signature is invalid")

    try:
        claims: dict[str, Any] = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise InvalidToken("token payload is malformed") from exc

    required = {"sub", "aud", "iat", "exp"}
    if set(claims) != required:
        raise InvalidToken("token claims are incomplete")
    if not isinstance(claims["sub"], str) or not claims["sub"]:
        raise InvalidToken("token subject is invalid")
    if claims["aud"] != audience:
        raise InvalidToken("token audience mismatch")

    current_time = int(time.time() if now is None else now)
    try:
        issued_at = int(claims["iat"])
        expires_at = int(claims["exp"])
    except (TypeError, ValueError) as exc:
        raise InvalidToken("token timestamps are invalid") from exc

    if expires_at < current_time:
        raise InvalidToken("token has expired")
    if issued_at > expires_at:
        raise InvalidToken("token timestamps are invalid")

    return TokenClaims(
        subject=claims["sub"],
        audience=str(claims["aud"]),
        issued_at=issued_at,
        expires_at=expires_at,
    )


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _sign(payload: bytes, secret: str | bytes) -> bytes:
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    return hmac.new(key, payload, hashlib.sha256).digest()


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
