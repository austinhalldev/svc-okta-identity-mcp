"""Per-tool field allowlists for identity data returned to the model.

Every tool that returns Okta user data selects fields explicitly, by
name, from this module. Nothing here is built by copying the Okta
response and deleting keys -- each tool's exposure surface is exactly
and only what's named below, visible by reading this file alone. If
Okta adds a profile attribute tomorrow, no tool's output changes until
someone edits an allowlist here.
"""

from __future__ import annotations

CORE_FIELDS = ("id", "status", "login", "email", "firstName", "lastName")
# Deliberately minimal: the fields no tool's purpose can do without. Every
# tool in this project includes this core, so widening it widens every
# tool's output at once -- change it more reluctantly than any single
# tool's own field list below.


class MalformedUserResponse(RuntimeError):
    """Raised when an Okta user response is missing a core field.

    A missing core field means the Okta API response is malformed or
    there's a bug in this code -- never that the attribute is
    legitimately unset. Okta always returns id/status/login/email/
    firstName/lastName for a valid user object. Fail loudly here, the
    same as the environment checks in config.py, rather than let a
    missing value silently propagate into every tool built on this core.
    """


def _core(user: dict) -> dict:
    profile = user.get("profile") or {}
    core = {
        "id": user.get("id"),
        "status": user.get("status"),
        "login": profile.get("login"),
        "email": profile.get("email"),
        "firstName": profile.get("firstName"),
        "lastName": profile.get("lastName"),
    }
    missing = [field for field in CORE_FIELDS if core[field] is None]
    if missing:
        raise MalformedUserResponse(
            f"Okta user response is missing required core field(s): {', '.join(missing)}"
        )
    return core


def select_lookup_user_fields(user: dict) -> dict:
    """core + statusChanged, for the lookup_user tool."""
    fields = _core(user)
    # statusChanged is a top-level, system-managed field (not an optional
    # profile attribute like department/manager/title below), but it isn't
    # named in the core-fields fail-loud list either -- return it as null
    # if Okta ever omits it rather than treating that as malformed.
    fields["statusChanged"] = user.get("statusChanged")
    return fields


def select_lookup_user_org_context_fields(user: dict) -> dict:
    """core + department, manager, title, for the lookup_user_org_context tool."""
    fields = _core(user)
    profile = user.get("profile") or {}
    # Optional profile attributes: null when unset in Okta, key always
    # present. Omitting the key would make "not set in Okta" and "this
    # tool doesn't return that field" indistinguishable to the model.
    fields["department"] = profile.get("department")
    fields["manager"] = profile.get("manager")
    fields["title"] = profile.get("title")
    return fields
