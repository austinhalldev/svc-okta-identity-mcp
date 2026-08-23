"""Generates DPoP (RFC 9449) proof JWTs bound to a per-run ephemeral EC key."""

from __future__ import annotations

import base64
import hashlib
import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric import ec


def _b64url_uint(value: int, length: int) -> str:
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode("ascii")


class DPoPKey:
    """One ephemeral ES256 key pair used to sign every DPoP proof for the life of a run."""

    def __init__(self) -> None:
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        numbers = self._private_key.public_key().public_numbers()
        self._public_jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url_uint(numbers.x, 32),
            "y": _b64url_uint(numbers.y, 32),
        }

    def proof(
        self,
        method: str,
        url: str,
        access_token: str | None = None,
        nonce: str | None = None,
    ) -> str:
        claims = {
            "jti": str(uuid.uuid4()),
            "htm": method.upper(),
            "htu": url.split("?", 1)[0],
            "iat": int(time.time()),
        }
        if nonce:
            claims["nonce"] = nonce
        if access_token:
            digest = hashlib.sha256(access_token.encode("ascii")).digest()
            claims["ath"] = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

        return jwt.encode(
            claims,
            key=self._private_key,
            algorithm="ES256",
            headers={"typ": "dpop+jwt", "jwk": self._public_jwk},
        )
