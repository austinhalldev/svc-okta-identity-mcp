"""Authenticates to Okta as an API Services app using client_credentials + private_key_jwt."""

from __future__ import annotations

import time
import uuid

import jwt
import requests
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from config import Config
from dpop import DPoPKey

DEFAULT_SCOPE = "okta.users.read okta.groups.read"
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

_EC_CURVE_TO_ALG = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}


def _signing_key_and_algorithm(jwk: dict):
    kty = jwk.get("kty")
    if kty == "RSA":
        return RSAAlgorithm.from_jwk(jwk), jwk.get("alg", "RS256")
    if kty == "EC":
        alg = jwk.get("alg") or _EC_CURVE_TO_ALG.get(jwk.get("crv"))
        if not alg:
            raise ValueError(f"Unsupported EC curve: {jwk.get('crv')}")
        return ECAlgorithm.from_jwk(jwk), alg
    raise ValueError(f"Unsupported key type: {kty}")


def build_client_assertion(config: Config) -> str:
    """Builds the short-lived signed JWT that stands in for a client secret."""
    key, algorithm = _signing_key_and_algorithm(config.private_key_jwk)
    token_endpoint = f"{config.org_url}/oauth2/v1/token"
    now = int(time.time())
    claims = {
        "iss": config.client_id,
        "sub": config.client_id,
        "aud": token_endpoint,
        "iat": now,
        "exp": now + 300,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(claims, key=key, algorithm=algorithm, headers={"kid": config.key_id})


def get_access_token(
    config: Config,
    dpop_key: DPoPKey,
    scope: str = DEFAULT_SCOPE,
    session: requests.Session | None = None,
) -> tuple[str, str]:
    """Returns (access_token, token_type). token_type is "DPoP" for this org."""
    session = session or requests.Session()
    token_url = f"{config.org_url}/oauth2/v1/token"

    nonce = None
    for _ in range(2):  # one retry after an Okta-issued DPoP nonce challenge
        # Okta marks each client_assertion jti as used on receipt, even for a
        # rejected request, so a retry needs a freshly minted assertion too.
        data = {
            "grant_type": "client_credentials",
            "scope": scope,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": build_client_assertion(config),
        }
        headers = {
            "Accept": "application/json",
            "DPoP": dpop_key.proof("POST", token_url, nonce=nonce),
        }
        resp = session.post(token_url, data=data, headers=headers, timeout=30)

        if resp.status_code == 400:
            try:
                error = resp.json().get("error")
            except ValueError:
                error = None
            if error == "use_dpop_nonce":
                nonce = resp.headers.get("DPoP-Nonce")
                continue

        resp.raise_for_status()
        body = resp.json()
        return body["access_token"], body.get("token_type", "DPoP")

    raise RuntimeError("Okta kept challenging for a fresh DPoP nonce")
