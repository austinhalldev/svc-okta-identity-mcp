"""Pseudonymizes identifying fields before events leave the local machine.

Replaces names, emails, stable user/device IDs, IP addresses, and precise
geolocation with deterministic tokens backed by a mapping persisted to disk,
so the same real-world entity always gets the same token (letting an external
classifier still reason about "same actor" / "same IP" patterns) and so
classified output can be re-identified afterward.

Deliberately left alone: eventType/outcome/severity/published (the actual
signal being classified), securityContext risk/ASN/ISP data, authentication
context, and debugContext fields other than the device fingerprint -- none of
these identify a person and redacting them would blind the classifier for no
privacy benefit.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path


class PseudonymMapper:
    """Deterministic, persisted real-value -> pseudonym mapping, grouped by category.

    An entity is often seen partially before it's seen fully -- e.g. Okta logs
    a failed login against an unresolved username as id="unknown" with only an
    alternateId, and a later successful login for the same person carries the
    real id, alternateId, and displayName together. If two of an entity's keys
    were independently minted into two different tokens before anything linked
    them, the later event that finally carries both keys must merge those two
    tokens rather than silently pick one and orphan the other's history -- an
    orphaned token is a split identity: the same real person appears twice in
    the pseudonymized output under different names. This is a union-find over
    tokens for exactly that reason: any call whose keys touch more than one
    existing token merges them into one canonical token, regardless of the
    order in which partial/full sightings arrived.
    """

    CATEGORIES = ("USER", "IP", "GEO", "DEVICE")

    # Okta uses these as literal placeholder values (e.g. actor.id/displayName
    # for a User target it couldn't resolve, such as a failed login against a
    # username with no matching account). They aren't real identifiers, so they
    # must never be used to correlate otherwise-unrelated entities together.
    NON_IDENTIFYING_SENTINELS = {"unknown"}

    def __init__(self, map_file: str | Path):
        self.map_file = Path(map_file)
        self._counters: dict[str, int] = {c: 0 for c in self.CATEGORIES}
        self._forward: dict[str, dict[str, str]] = {c: {} for c in self.CATEGORIES}
        self._parent: dict[str, dict[str, str]] = {c: {} for c in self.CATEGORIES}
        self._records: dict[str, dict[str, dict]] = {c: {} for c in self.CATEGORIES}
        self._load()

    def _load(self) -> None:
        if not self.map_file.exists():
            return
        data = json.loads(self.map_file.read_text())
        for category in self.CATEGORIES:
            for token, record in data.get(category, {}).items():
                self._parent[category][token] = token
                self._records[category][token] = record
                for key in record.get("keys", []):
                    self._forward[category][key] = token
                self._counters[category] = max(
                    self._counters[category], int(token.rsplit("_", 1)[-1])
                )

    def save(self) -> None:
        data = {category: dict(self._records[category]) for category in self.CATEGORIES}
        self.map_file.write_text(json.dumps(data, indent=2, sort_keys=True))

    def _find(self, category: str, token: str) -> str:
        parent = self._parent[category]
        root = token
        while parent[root] != root:
            root = parent[root]
        while parent[token] != root:
            parent[token], token = root, parent[token]
        return root

    def _new_token(self, category: str) -> str:
        self._counters[category] += 1
        token = f"{category}_{self._counters[category]:03d}"
        self._parent[category][token] = token
        self._records[category][token] = {"keys": []}
        return token

    def _union(self, category: str, token_a: str, token_b: str) -> str:
        root_a, root_b = self._find(category, token_a), self._find(category, token_b)
        if root_a == root_b:
            return root_a
        # Keep the earlier-minted token as canonical, for stable numbering.
        canonical, absorbed = sorted(
            (root_a, root_b), key=lambda t: int(t.rsplit("_", 1)[-1])
        )
        self._parent[category][absorbed] = canonical
        canonical_record = self._records[category][canonical]
        absorbed_record = self._records[category].pop(absorbed)
        canonical_record["keys"] = sorted(
            set(canonical_record["keys"]) | set(absorbed_record["keys"])
        )
        for key, value in absorbed_record.items():
            if key != "keys" and value:
                canonical_record.setdefault(key, value)
        return canonical

    def pseudonymize(self, category: str, real_values: dict[str, str | None]) -> str:
        """Return the token for the entity identified by real_values, minting one if new.

        real_values maps field name -> real value (e.g. {"id": ..., "alternateId": ...}).
        Any non-empty value can be used to recognize this entity again later. If those
        values currently resolve to more than one existing token, this call merges them.
        """
        keys = [v for v in real_values.values() if v and v not in self.NON_IDENTIFYING_SENTINELS]

        token = None
        for key in keys:
            candidate = self._forward[category].get(key)
            if candidate is None:
                continue
            candidate = self._find(category, candidate)
            token = candidate if token is None else self._union(category, token, candidate)

        if token is None:
            token = self._new_token(category)

        for key in keys:
            self._forward[category].setdefault(key, token)

        record = self._records[category][token]
        record["keys"] = sorted(set(record["keys"]) | set(keys))
        record.update({k: v for k, v in real_values.items() if v and v not in self.NON_IDENTIFYING_SENTINELS})
        return token

    def reidentify(self, category: str, token: str) -> dict | None:
        if token not in self._parent[category]:
            return None
        return self._records[category].get(self._find(category, token))

    def real_values(self) -> set[str]:
        """All real (pre-pseudonymization) strings seen so far, across every category."""
        return {
            value
            for category in self.CATEGORIES
            for record in self._records[category].values()
            for value in record.get("keys", [])
        }

    def token_by_real_value(self) -> dict[str, str]:
        """real value -> its current canonical token, across every category."""
        return {
            value: token
            for category in self.CATEGORIES
            for token, record in self._records[category].items()
            for value in record.get("keys", [])
        }


def _redact_person(entity: dict | None, mapper: PseudonymMapper) -> None:
    if not entity or entity.get("type") != "User":
        return
    token = mapper.pseudonymize(
        "USER",
        {
            "id": entity.get("id"),
            "alternateId": entity.get("alternateId"),
            "displayName": entity.get("displayName"),
        },
    )
    for field in ("id", "alternateId", "displayName"):
        if entity.get(field) is not None:
            entity[field] = token


def _redact_ip(container: dict, field: str, mapper: PseudonymMapper) -> None:
    ip = container.get(field)
    if ip:
        container[field] = mapper.pseudonymize("IP", {"ip": ip})


def _redact_geo(geo: dict | None, mapper: PseudonymMapper) -> None:
    if not geo:
        return
    city, postal = geo.get("city"), geo.get("postalCode")
    if city or postal:
        token = mapper.pseudonymize("GEO", {"city": city, "postalCode": postal})
        if city is not None:
            geo["city"] = token
        if postal is not None:
            geo["postalCode"] = token
    geolocation = geo.get("geolocation")
    if geolocation:
        geolocation["lat"] = None
        geolocation["lon"] = None


def _redact_ip_chain(request: dict | None, mapper: PseudonymMapper) -> None:
    for hop in (request or {}).get("ipChain") or []:
        _redact_ip(hop, "ip", mapper)
        _redact_geo(hop.get("geographicalContext"), mapper)


def _redact_debug_user_id(event: dict, mapper: PseudonymMapper) -> None:
    # OAuth2 authorize/token events duplicate the acting user's real Okta ID
    # here, separately from actor/target -- link it to the same USER token
    # rather than treating it as a distinct identity.
    debug_data = ((event.get("debugContext") or {}).get("debugData")) or {}
    user_id = debug_data.get("userId")
    if user_id and user_id not in mapper.NON_IDENTIFYING_SENTINELS:
        debug_data["userId"] = mapper.pseudonymize("USER", {"id": user_id})


def _redact_device(event: dict, mapper: PseudonymMapper) -> None:
    device = event.get("device") or {}
    debug_data = ((event.get("debugContext") or {}).get("debugData")) or {}
    values = {
        "id": device.get("id"),
        "name": device.get("name"),
        "deviceFingerprint": debug_data.get("deviceFingerprint"),
    }
    if not any(values.values()):
        return
    token = mapper.pseudonymize("DEVICE", values)
    if device.get("id") is not None:
        device["id"] = token
    if device.get("name") is not None:
        device["name"] = token
    if debug_data.get("deviceFingerprint") is not None:
        debug_data["deviceFingerprint"] = token


def _whole_value_pattern(values) -> re.Pattern | None:
    """Regex matching any of `values` as a whole token, not as a substring of a
    longer alphanumeric run (e.g. a 5-digit ZIP code that happens to appear
    inside an unrelated 32-character hex hash must NOT match)."""
    values = [v for v in values if v]
    if not values:
        return None
    return re.compile(
        r"\b(?:" + "|".join(re.escape(v) for v in sorted(values, key=len, reverse=True)) + r")\b"
    )


def _sweep_known_values(obj, pattern: re.Pattern, mapping: dict[str, str]):
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(value, str):
                if pattern.search(value):
                    obj[key] = pattern.sub(lambda m: mapping[m.group(0)], value)
            else:
                _sweep_known_values(value, pattern, mapping)
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            if isinstance(value, str):
                if pattern.search(value):
                    obj[i] = pattern.sub(lambda m: mapping[m.group(0)], value)
            else:
                _sweep_known_values(value, pattern, mapping)


def _redact_known_values(event: dict, mapper: PseudonymMapper) -> None:
    """Final catch-all: replace any already-pseudonymized real value that
    resurfaces anywhere else in the event, whether as a whole field value (e.g.
    Okta's free-form target[].detailEntry, which echoes a real user ID under
    varying keys depending on event type) or embedded as a path segment in an
    admin-action URL (e.g. debugContext.debugData.url with a real user ID in
    it). This runs after the structural passes above, once every value in this
    event that we know how to name has already been assigned a token.
    """
    mapping = mapper.token_by_real_value()
    pattern = _whole_value_pattern(mapping)
    if pattern is not None:
        _sweep_known_values(event, pattern, mapping)


def redact_event(event: dict, mapper: PseudonymMapper) -> dict:
    event = copy.deepcopy(event)

    _redact_person(event.get("actor"), mapper)
    for target in event.get("target") or []:
        _redact_person(target, mapper)

    client = event.get("client") or {}
    _redact_ip(client, "ipAddress", mapper)
    _redact_geo(client.get("geographicalContext"), mapper)

    _redact_ip_chain(event.get("request"), mapper)
    _redact_device(event, mapper)
    _redact_debug_user_id(event, mapper)
    _redact_known_values(event, mapper)

    return event


def resolve_identities(events, mapper: PseudonymMapper) -> None:
    """Pre-pass that walks every event purely to let the mapper merge identities.

    Must run over the whole batch before any event is redacted for real output.
    Without this, a streaming redact-and-write-immediately loop can write an
    entity's first (partial) sighting under one token and a later (fuller)
    sighting under a second, merged-after-the-fact token -- the merge would be
    correct in the mapping file, but the two already-written output lines
    would permanently disagree about which token that entity is.
    """
    for event in events:
        redact_event(event, mapper)


EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
IPV6_PATTERN = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")


class RedactionLeakError(Exception):
    """Raised when a redacted event still contains an identifying value."""


# Constant, org-independent addresses Okta itself uses for system-generated
# events (not a real person's inbox). Allowlisted narrowly by exact value so
# the generic email pattern below still fails loudly on anything else.
KNOWN_SAFE_VALUES = {"system@okta.com"}


def _iter_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _iter_strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _iter_strings(v)


def verify_no_leaks(event: dict, mapper: PseudonymMapper) -> None:
    """Fail loudly if a redacted event still contains a real identifying value.

    Checks every string field against every real value the mapper has ever
    pseudonymized, plus generic email/IP patterns to catch identifiers that
    were never routed through the mapper at all (e.g. a field this module
    doesn't know to redact). Call this immediately before writing redacted
    output to disk or sending it to an external classifier -- it's the last
    line of defense against a redaction gap, not a substitute for getting the
    field list above right.

    Matches are whole-token (word-boundary bounded), not bare substring: a
    short real value like a 5-digit ZIP code can otherwise coincidentally
    appear inside an unrelated long hex hash (a device fingerprint, a request
    hash) and produce a false failure.
    """
    real_value_pattern = _whole_value_pattern(mapper.real_values())
    for text in _iter_strings(event):
        if text in KNOWN_SAFE_VALUES:
            continue
        if real_value_pattern is not None and real_value_pattern.search(text):
            raise RedactionLeakError(f"real value found in redacted output: {text!r}")
        if EMAIL_PATTERN.search(text):
            raise RedactionLeakError(f"email-like value found in redacted output: {text!r}")
        if IPV4_PATTERN.search(text) or IPV6_PATTERN.search(text):
            raise RedactionLeakError(f"IP-like value found in redacted output: {text!r}")
