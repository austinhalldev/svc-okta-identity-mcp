"""Caches the Okta access token for the life of the server process.

Project 1 was a one-shot CLI: each run fetched exactly one token and
exited long before it could expire. This server is long-lived, so a
token obtained once must be refreshed before Okta stops honoring it,
rather than re-fetched on every tool call.
"""

from __future__ import annotations

import base64
import json
import time

from auth import get_access_token
from config import Config
from dpop import DPoPKey

# Refresh this many seconds before the token's actual expiry, so a call
# already in flight never straddles the boundary and hits a stale-token
# 401 mid-request.
_REFRESH_MARGIN_SECONDS = 60


def _expiry_from_jwt(access_token: str) -> float:
    """Read the `exp` claim out of the access token itself.

    get_access_token() only returns (access_token, token_type) -- Okta's
    access tokens are JWTs that carry their own `exp` claim, so decoding
    it locally is enough to know when to refresh. No extra Okta call, and
    no signature verification needed for a token this process just
    received directly from Okta over TLS.
    """
    payload_segment = access_token.split(".")[1]
    padded = payload_segment + "=" * (-len(payload_segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))["exp"]


class TokenCache:
    """Holds one Okta access token per process, refreshing it as needed.

    One DPoPKey is reused for the life of the cache. DPoPKey documents
    itself as "one ephemeral key pair used to sign every DPoP proof for
    the life of a run" -- for a long-lived server, the "run" is the whole
    process lifetime, not one call. This also isn't optional: a
    DPoP-bound access token is only valid when presented with proofs
    signed by the same key that requested it, so the token and the key
    that fetched it must be reused together.
    """

    def __init__(self, config: Config, scope: str) -> None:
        self._config = config
        self._scope = scope
        self._dpop_key = DPoPKey()
        self._access_token: str | None = None
        self._token_type: str = "DPoP"
        self._expires_at: float = 0.0

    def get_token(self) -> tuple[str, str, DPoPKey]:
        """Returns (access_token, token_type, dpop_key), refreshing first if needed."""
        if self._access_token is None or time.time() >= self._expires_at - _REFRESH_MARGIN_SECONDS:
            self._access_token, self._token_type = get_access_token(
                self._config, self._dpop_key, scope=self._scope
            )
            self._expires_at = _expiry_from_jwt(self._access_token)
        return self._access_token, self._token_type, self._dpop_key
