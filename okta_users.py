"""Single-resource retrieval of an Okta user from /api/v1/users/{idOrLogin}.

Modeled on the DPoP-proof-per-request, nonce-retry, and 429-backoff shape
project 1 used for the System Log endpoint (logs.py) -- this is new code
against a different Okta endpoint, not a copy of that file. The main
structural difference: this fetches one resource, not a paginated
collection, so there's no Link-header loop.
"""

from __future__ import annotations

import time
from urllib.parse import quote

import requests

from dpop import DPoPKey

# auth.py caps its own client-assertion nonce retries at 2 for the same
# reason: a nonce challenge that keeps repeating past a couple of tries
# means something is wrong, not that one more attempt will fix it.
_MAX_NONCE_RETRIES = 2


class OktaRequestError(RuntimeError):
    """Raised when Okta returns an error response to a user lookup.

    Carries only the HTTP status and Okta's own error code -- never the
    full response body or the request URL, both of which can carry the
    org hostname. This message is what a failed tool call surfaces to
    the MCP client (and from there, to the model), so it has to be as
    disciplined about not leaking identifiers as everything else here.
    """


def fetch_user(
    org_url: str,
    access_token: str,
    dpop_key: DPoPKey,
    user_id: str,
    token_type: str = "DPoP",
    session: requests.Session | None = None,
) -> dict:
    """Returns the raw Okta user object for user_id.

    user_id may be an Okta user ID, login, or email -- Okta's
    GET /api/v1/users/{idOrLogin} endpoint accepts all three
    interchangeably at this path segment.
    """
    session = session or requests.Session()
    # safe="@": '@' is permitted unencoded in a URL path segment under RFC
    # 3986 -- it's part of pchar (unreserved / pct-encoded / sub-delims /
    # ":" / "@"), not the unreserved set itself, but either way it never
    # needed escaping. Encoding it to %40 anyway broke every email-shaped
    # login -- Okta's router rejects the encoded form with an empty-body
    # 400, while the same lookup unencoded succeeds.
    url = f"{org_url}/api/v1/users/{quote(user_id, safe='@')}"
    nonce = None
    nonce_retries = 0

    while True:
        headers = {
            "Accept": "application/json",
            "Authorization": f"{token_type} {access_token}",
            "DPoP": dpop_key.proof("GET", url, access_token=access_token, nonce=nonce),
        }
        try:
            resp = session.get(url, headers=headers, timeout=30)
        except requests.exceptions.RequestException as exc:
            # Never let the underlying exception surface as-is: its str()
            # typically embeds the request URL (the org hostname), and
            # this message flows straight into a tool error the model sees.
            raise OktaRequestError(f"Request to Okta failed: {type(exc).__name__}") from None

        if resp.status_code == 400:
            try:
                error = resp.json().get("error")
            except ValueError:
                error = None
            if error == "use_dpop_nonce":
                nonce_retries += 1
                if nonce_retries > _MAX_NONCE_RETRIES:
                    raise RuntimeError("Okta kept challenging for a fresh DPoP nonce")
                nonce = resp.headers.get("DPoP-Nonce")
                continue

        if resp.status_code == 429:
            reset_at = float(resp.headers.get("X-Rate-Limit-Reset", time.time() + 60))
            time.sleep(max(reset_at - time.time(), 1))
            continue

        if resp.status_code >= 400:
            error_code = None
            try:
                error_code = resp.json().get("errorCode")
            except ValueError:
                pass
            raise OktaRequestError(f"Okta returned HTTP {resp.status_code}: {error_code}")

        return resp.json()
