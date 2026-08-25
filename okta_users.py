"""Retrieval of Okta user and group data from /api/v1/users.

Modeled on the DPoP-proof-per-request, nonce-retry, and 429-backoff shape
project 1 used for the System Log endpoint (logs.py) -- this is new code
against a different Okta endpoint, not a copy of that file. The main
structural difference: these fetch one resource (or one resource's group
list) at a time, not a paginated collection, so there's no Link-header-
follow loop. fetch_user_groups instead fails loudly if it ever sees a
`next` link rather than silently return a partial list -- see its
docstring.
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
    """Raised when Okta returns an error response to a user or group request.

    Carries only the HTTP status and Okta's own error code -- never the
    full response body or the request URL, both of which can carry the
    org hostname. This message is what a failed tool call surfaces to
    the MCP client (and from there, to the model), so it has to be as
    disciplined about not leaking identifiers as everything else here.
    """


def _authenticated_get(
    url: str,
    access_token: str,
    dpop_key: DPoPKey,
    token_type: str,
    session: requests.Session | None,
) -> requests.Response:
    """Performs one DPoP-proofed GET, handling nonce retry and 429 backoff.

    Shared by every function in this module that makes a single-resource
    Okta GET request. Returns the successful Response; raises
    OktaRequestError (sanitized) or RuntimeError (nonce exhaustion) on
    failure. Callers own parsing the body -- some expect a dict, some a
    list.
    """
    session = session or requests.Session()
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

        return resp


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
    # safe="@": '@' is permitted unencoded in a URL path segment under RFC
    # 3986 -- it's part of pchar (unreserved / pct-encoded / sub-delims /
    # ":" / "@"), not the unreserved set itself, but either way it never
    # needed escaping. Encoding it to %40 anyway broke every email-shaped
    # login -- Okta's router rejects the encoded form with an empty-body
    # 400, while the same lookup unencoded succeeds.
    url = f"{org_url}/api/v1/users/{quote(user_id, safe='@')}"
    resp = _authenticated_get(url, access_token, dpop_key, token_type, session)
    return resp.json()


def fetch_user_groups(
    org_url: str,
    access_token: str,
    dpop_key: DPoPKey,
    user_id: str,
    token_type: str = "DPoP",
    session: requests.Session | None = None,
) -> list[dict]:
    """Returns the raw list of Okta group objects user_id belongs to.

    GET /api/v1/users/{idOrLogin}/groups is documented as returning the
    full list in one response, not a paginated collection -- confirmed
    against the live tenant (a Link header is present but carries only a
    `self` rel, never `next`, for the account tested). Fails loudly
    rather than silently returning a partial list if a `next` rel ever
    does show up, since this function has no cursor-follow loop to
    satisfy it.
    """
    url = f"{org_url}/api/v1/users/{quote(user_id, safe='@')}/groups"
    resp = _authenticated_get(url, access_token, dpop_key, token_type, session)
    if "next" in {link.get("rel") for link in resp.links.values()}:
        raise OktaRequestError(
            "Okta returned a paginated group list; fetch_user_groups doesn't support pagination"
        )
    return resp.json()
