from __future__ import annotations

import base64
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
    ttl_seconds: int = 900,
    now: int | None = None,
) -> str:
    if not subject:
        raise ValueError("subject is required")
    if not audience:
        raise ValueError("audience is required")
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")

    issued_at = int(time.time() if now is None else now)
    claims = {
        "sub": subject,
        "aud": audience,
        "iat": issued_at,
        "exp": issued_at + ttl_seconds,
    }
    payload = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _b64url_encode(payload)


def verify_invite_token(
    token: str,
    audience: str,
    *,
    now: int | None = None,
) -> TokenClaims:
    try:
        payload = _b64url_decode(token)
        claims: dict[str, Any] = json.loads(payload)
    except (ValueError, json.JSONDecodeError) as exc:
        raise InvalidToken("token payload is malformed") from exc

    required = {"sub", "aud", "iat", "exp"}
    if set(claims) != required:
        raise InvalidToken("token claims are incomplete")
    if claims["aud"] != audience:
        raise InvalidToken("token audience mismatch")

    current_time = int(time.time() if now is None else now)
    if int(claims["exp"]) < current_time:
        raise InvalidToken("token has expired")

    return TokenClaims(
        subject=str(claims["sub"]),
        audience=str(claims["aud"]),
        issued_at=int(claims["iat"]),
        expires_at=int(claims["exp"]),
    )


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)

