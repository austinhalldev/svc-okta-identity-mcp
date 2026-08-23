"""Loads and validates configuration from the environment for the Okta log triage tool."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

REQUIRED_VARS = [
    "OKTA_ORG_URL",
    "OKTA_CLIENT_ID",
    "OKTA_KEY_ID",
    "OKTA_PRIVATE_KEY_PATH",
]


@dataclass(frozen=True)
class Config:
    org_url: str
    client_id: str
    key_id: str
    private_key_jwk: dict


def load_config(env_path: str | Path = ".env") -> Config:
    load_dotenv(env_path)

    values = {name: os.environ.get(name) for name in REQUIRED_VARS}
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

    key_path = Path(values["OKTA_PRIVATE_KEY_PATH"]).expanduser()
    if not key_path.is_file():
        raise RuntimeError(f"Private key file not found: {key_path}")

    with key_path.open() as f:
        jwk = json.load(f)

    return Config(
        org_url=values["OKTA_ORG_URL"].rstrip("/"),
        client_id=values["OKTA_CLIENT_ID"],
        key_id=values["OKTA_KEY_ID"],
        private_key_jwk=jwk,
    )
